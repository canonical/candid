// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"crypto/rand"
	"encoding"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"gopkg.in/CanonicalLtd/candidclient.v1"
	"gopkg.in/CanonicalLtd/candidclient.v1/params"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/names.v2"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"
	"gopkg.in/macaroon.v2"

	"github.com/CanonicalLtd/candid/internal/auth"
	"github.com/CanonicalLtd/candid/internal/auth/httpauth"
	"github.com/CanonicalLtd/candid/internal/identity"
	"github.com/CanonicalLtd/candid/store"
)

// thirdPartyCaveatChecker implements an
// httpbakery.ThirdPartyCaveatChecker for the identity service.
type thirdPartyCaveatChecker struct {
	params  identity.HandlerParams
	reqAuth *httpauth.Authorizer
	checker *bakery.Checker
	place   *place
}

// CheckThirdPartyCaveat implements httpbakery.ThirdPartyCaveatChecker.
// It acquires a handler before checking the caveat, so that we have a
// database connection for the purpose.
func (c *thirdPartyCaveatChecker) CheckThirdPartyCaveat(ctx context.Context, p httpbakery.ThirdPartyCaveatCheckerParams) ([]checkers.Caveat, error) {
	t := trace.New(p.Request.URL.Path, "")
	defer t.Finish()
	return c.checkThirdPartyCaveat(trace.NewContext(ctx, t), p)
}

// checkThirdPartyCaveat checks the given caveat. This function is called
// by the httpbakery discharge logic. See httpbakery.DischargeHandler
// for futher details.
//
// This is implemented as a separate method so that it can be called from
// WaitLegacy without nesting the trace context.
func (c *thirdPartyCaveatChecker) checkThirdPartyCaveat(ctx context.Context, p httpbakery.ThirdPartyCaveatCheckerParams) ([]checkers.Caveat, error) {

	domain := ""
	if c, err := p.Request.Cookie("domain"); err == nil && names.IsValidUserDomain(c.Value) {
		domain = c.Value
	}
	cond, args, err := checkers.ParseCaveat(string(p.Caveat.Condition))
	if err != nil {
		return nil, errgo.WithCausef(err, params.ErrBadRequest, "cannot parse caveat %q", p.Caveat.Condition)
	}
	var op bakery.Op
	switch cond {
	case "is-authenticated-user":
		op = auth.GlobalOp(auth.ActionDischarge)
		if len(args) == 0 {
			break
		}
		if args[0] != '@' {
			return nil, checkers.ErrCaveatNotRecognized
		}
		if !names.IsValidUserDomain(args[1:]) {
			return nil, errgo.WithCausef(err, params.ErrBadRequest, "invalid domain %q", args[1:])
		}
		domain = args[1:]
		ctx = auth.ContextWithRequiredDomain(ctx, domain)
	case "is-member-of":
		op = auth.GroupsDischargeOp(strings.Fields(args))
	default:
		return nil, checkers.ErrCaveatNotRecognized
	}

	var mss []macaroon.Slice
	if user := p.Request.Form.Get("discharge-for-user"); user != "" {
		_, err = c.reqAuth.Auth(ctx, p.Request, auth.GlobalOp(auth.ActionDischargeFor))
		if err != nil {
			return nil, errgo.Mask(err, errgo.Is(params.ErrUnauthorized), isDischargeRequiredError)
		}
		ctx = auth.ContextWithUsername(ctx, user)
	} else if p.Token != nil {
		tokenMacaroons, err := macaroonsFromDischargeToken(ctx, p.Token)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		mss = []macaroon.Slice{tokenMacaroons}
	} else {
		// If no discharge token has been provided, include macaroons
		// from the request too, to enable clients to re-use previous discharge tokens that
		// have been returned as cookies.
		mss = httpbakery.RequestMacaroons(p.Request)
	}

	authInfo, err := c.params.Authorizer.Auth(ctx, mss, op)
	if _, ok := errgo.Cause(err).(*bakery.DischargeRequiredError); ok {
		return nil, c.interactionRequiredError(ctx, interactionRequiredParams{
			why: err,
			req: p.Request,
			info: &dischargeRequestInfo{
				Caveat:    p.Caveat.Caveat,
				CaveatId:  p.Caveat.Id,
				Condition: string(p.Caveat.Condition),
				Origin:    p.Request.Header.Get("Origin"),
			},
			domain: domain,
		})
	}
	if err != nil {
		// TODO return appropriate error code when permission denied.
		return nil, errgo.Mask(err)
	}
	logger.Debugf("authorization for %#v succeeded", authInfo.Identity)
	c.updateDischargeTime(ctx, authInfo.Identity.Id())
	if cond == "is-member-of" {
		return nil, nil
	}
	if p.Token != nil && len(mss) > 0 {
		// As well as discharging the original third party caveat, also
		// set the discharge token macaroon as a cookie
		// so that it may be used for future discharges if appropriate
		// (it will be ignored otherwise).
		if err := setIdentityCookie(p.Response, mss[0]); err != nil {
			return nil, errgo.Mask(err)
		}
	}
	return []checkers.Caveat{
		candidclient.UserDeclaration(authInfo.Identity.Id()),
		checkers.TimeBeforeCaveat(time.Now().Add(24 * time.Hour)),
	}, nil
}

func macaroonsFromDischargeToken(ctx context.Context, token *httpbakery.DischargeToken) (macaroon.Slice, error) {
	var ms macaroon.Slice
	var v encoding.BinaryUnmarshaler
	switch token.Kind {
	default:
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "invalid token")
	case "agent":
		v = &ms
	case "macaroon":
		// TODO store a slice of macaroons in the token so
		// the format is the same in both cases.
		var m macaroon.Macaroon
		ms = macaroon.Slice{&m}
		v = &m
	}
	if err := v.UnmarshalBinary(token.Value); err != nil {
		return nil, errgo.WithCausef(err, params.ErrBadRequest, "invalid token")
	}
	return ms, nil
}

func (c *thirdPartyCaveatChecker) updateDischargeTime(ctx context.Context, username string) {
	err := c.params.Store.UpdateIdentity(
		ctx,
		&store.Identity{
			Username:      username,
			LastDischarge: time.Now(),
		}, store.Update{
			store.LastDischarge: store.Set,
		},
	)
	if err != nil {
		logger.Infof("unexpected error updating last discharge time: %s", err)
	}
}

type interactionRequiredParams struct {
	why         error
	req         *http.Request
	info        *dischargeRequestInfo
	dischargeID string
	domain      string
}

// interactionRequiredError returns an error suitable for returning from
// a discharge request that can only be satisfied if the user logs in.
func (c *thirdPartyCaveatChecker) interactionRequiredError(ctx context.Context, p interactionRequiredParams) error {
	dischargeID, err := newDischargeID()
	if err != nil {
		return errgo.Mask(err)
	}
	// TODO(rog) If the user is already logged in (username != ""),
	// we should perhaps just return an error here.
	if err := c.place.NewRendezvous(ctx, dischargeID, p.info); err != nil {
		return errgo.Notef(err, "cannot make rendezvous")
	}
	ierr := httpbakery.NewInteractionRequiredError(p.why, p.req)
	agent.SetInteraction(ierr, agentURL(c.params.Location, dischargeID))
	for _, idp := range c.params.IdentityProviders {
		if p.domain != "" && idp.Domain() != p.domain {
			// The client has specified a domain and the idp is not in that domain,
			// so omit it.
			continue
		}
		idp.SetInteraction(ierr, dischargeID)
	}
	visitParams := "?did=" + dischargeID
	if p.domain != "" {
		visitParams += "&domain=" + url.QueryEscape(p.domain)
	}
	visitURL := c.params.Location + "/login" + visitParams
	waitTokenURL := c.params.Location + "/wait-token?did=" + dischargeID
	httpbakery.SetWebBrowserInteraction(ierr, visitURL, waitTokenURL)

	// Set the URLs used by old clients for backward compatibility.
	legacyVisitURL := c.params.Location + "/login-legacy" + visitParams
	legacyWaitURL := c.params.Location + "/wait-legacy?did=" + dischargeID
	httpbakery.SetLegacyInteraction(ierr, legacyVisitURL, legacyWaitURL)
	return ierr
}

func isDischargeRequiredError(err error) bool {
	cause, ok := errgo.Cause(err).(*httpbakery.Error)
	return ok && cause.Code == httpbakery.ErrDischargeRequired
}

func newDischargeID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errgo.Notef(err, "cannot read random bytes for discharge id")
	}
	return fmt.Sprintf("%x", b[:]), nil
}
