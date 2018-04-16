// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"crypto/sha256"
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
	dischargeID := dischargeID(p.Caveat)
	ctx = auth.ContextWithDischargeID(ctx, dischargeID)
	interactionRequiredParams := interactionRequiredParams{
		req: p.Request,
		info: &dischargeRequestInfo{
			Caveat:    p.Caveat.Caveat,
			CaveatId:  p.Caveat.Id,
			Condition: string(p.Caveat.Condition),
			Origin:    p.Request.Header.Get("Origin"),
		},
		dischargeID: dischargeID,
	}

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
	interactionRequiredParams.domain = domain
	// TODO add discharge id to context

	var mss []macaroon.Slice
	if user := p.Request.Form.Get("discharge-for-user"); user != "" {
		_, err = c.reqAuth.Auth(ctx, p.Request, auth.GlobalOp(auth.ActionDischargeFor))
		if err != nil {
			return nil, errgo.Mask(err, errgo.Is(params.ErrUnauthorized), isDischargeRequiredError)
		}
		ctx = auth.ContextWithUsername(ctx, user)
	} else if p.Token != nil {
		mss, err = c.macaroonsFromDischargeToken(ctx, p.Token)
		if err != nil {
			return nil, errgo.Mask(err)
		}
	}
	// Append any macaroons from the request so that we'll take
	// account of the identity cookie if present.
	mss = append(mss, httpbakery.RequestMacaroons(p.Request)...)

	authInfo, err := c.params.Authorizer.Auth(ctx, mss, op)
	if _, ok := errgo.Cause(err).(*bakery.DischargeRequiredError); ok {
		return nil, c.interactionRequiredError(ctx, interactionRequiredParams, err)
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
	return []checkers.Caveat{
		candidclient.UserDeclaration(authInfo.Identity.Id()),
		checkers.TimeBeforeCaveat(time.Now().Add(24 * time.Hour)),
	}, nil
}

func (c *thirdPartyCaveatChecker) macaroonsFromDischargeToken(ctx context.Context, token *httpbakery.DischargeToken) ([]macaroon.Slice, error) {
	var ms macaroon.Slice
	var v encoding.BinaryUnmarshaler
	switch token.Kind {
	default:
		return nil, errgo.WithCausef(nil, params.ErrBadRequest, "invalid token")
	case "agent":
		v = &ms
	case "macaroon":
		var m macaroon.Macaroon
		ms = macaroon.Slice{&m}
		v = &m
	}
	if err := v.UnmarshalBinary(token.Value); err != nil {
		return nil, errgo.WithCausef(err, params.ErrBadRequest, "invalid token")
	}
	return []macaroon.Slice{ms}, nil
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
	req         *http.Request
	info        *dischargeRequestInfo
	dischargeID string
	domain      string
}

// interactionRequiredError returns an error suitable for returning from
// a discharge request that can only be satisfied if the user logs in.
func (c *thirdPartyCaveatChecker) interactionRequiredError(ctx context.Context, p interactionRequiredParams, why error) error {
	// TODO(rog) If the user is already logged in (username != ""),
	// we should perhaps just return an error here.
	if err := c.place.NewRendezvous(ctx, p.dischargeID, p.info); err != nil {
		return errgo.Notef(err, "cannot make rendezvous")
	}
	ierr := httpbakery.NewInteractionRequiredError(why, p.req)
	agent.SetInteraction(ierr, c.params.Location+"/login/agent?did="+p.dischargeID)
	for _, idp := range c.params.IdentityProviders {
		if p.domain != "" && idp.Domain() != p.domain {
			// The client has specified a domain and the idp is not in that domain,
			// so omit it.
			continue
		}
		idp.SetInteraction(ierr, p.dischargeID)
	}
	visitParams := "?did=" + p.dischargeID
	if p.domain != "" {
		visitParams += "&domain=" + url.QueryEscape(p.domain)
	}
	visitURL := c.params.Location + "/login" + visitParams
	waitTokenURL := c.params.Location + "/wait-token?did=" + p.dischargeID
	httpbakery.SetWebBrowserInteraction(ierr, visitURL, waitTokenURL)

	// Set the URLs used by old clients for backward compatibility.
	legacyVisitURL := c.params.Location + "/login-legacy" + visitParams
	legacyWaitURL := c.params.Location + "/wait-legacy?did=" + p.dischargeID
	httpbakery.SetLegacyInteraction(ierr, legacyVisitURL, legacyWaitURL)
	return ierr
}

func isDischargeRequiredError(err error) bool {
	cause, ok := errgo.Cause(err).(*httpbakery.Error)
	return ok && cause.Code == httpbakery.ErrDischargeRequired
}

func dischargeID(ci *bakery.ThirdPartyCaveatInfo) string {
	sum := sha256.Sum256(ci.Caveat)
	return fmt.Sprintf("%x", sum[:8])
}
