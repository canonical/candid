// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package candidtest provides suites and functions useful for testing the
// identity manager.
package candidtest

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	qt "github.com/frankban/quicktest"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	macaroon "gopkg.in/macaroon.v2"
)

// DischargeCreator represents a third party service
// that creates discharges addressed to Candid.
type DischargeCreator struct {
	ServerURL string

	Bakery *identchecker.Bakery

	bakeryKey *bakery.KeyPair
}

// NewDischargeCreator returns a DischargeCreator that
// creates third party caveats addressed to the given server,
// which must be serving the "discharger" API.
func NewDischargeCreator(server *Server) *DischargeCreator {
	bakeryKey, err := bakery.GenerateKey()
	if err != nil {
		panic(err)
	}
	return &DischargeCreator{
		ServerURL: server.URL,
		Bakery: identchecker.NewBakery(identchecker.BakeryParams{
			Locator:        server,
			Key:            bakeryKey,
			IdentityClient: server.AdminIdentityClient(),
			Location:       "discharge-test",
		}),
		bakeryKey: bakeryKey,
	}
}

// AssertDischarge checks that a macaroon can be discharged with
// interaction using the specified visitor.
func (s *DischargeCreator) AssertDischarge(c *qt.C, i httpbakery.Interactor) {
	ms, err := s.Discharge(c, "is-authenticated-user", BakeryClient(i))
	c.Assert(err, qt.Equals, nil)
	_, err = s.Bakery.Checker.Auth(ms).Allow(context.Background(), identchecker.LoginOp)
	c.Assert(err, qt.Equals, nil)
}

// Discharge attempts to perform a discharge of a new macaroon against
// this suites identity server using the given client and returns a
// macaroon slice containing a discharged macaroon or any error. The
// newly minted macaroon will have a third-party caveat addressed to the
// identity server with the given condition.
func (s *DischargeCreator) Discharge(c *qt.C, condition string, client *httpbakery.Client) (macaroon.Slice, error) {
	return client.DischargeAll(context.Background(), s.NewMacaroon(c, condition, identchecker.LoginOp))
}

// NewMacaroon creates a new macaroon with a third-party caveat addressed
// to the identity server which has the given condition.
func (s *DischargeCreator) NewMacaroon(c *qt.C, condition string, op bakery.Op) *bakery.Macaroon {
	m, err := s.Bakery.Oven.NewMacaroon(
		context.Background(),
		bakery.LatestVersion,
		[]checkers.Caveat{{
			Location:  s.ServerURL,
			Condition: condition,
		}, checkers.TimeBeforeCaveat(time.Now().Add(time.Minute))},
		op,
	)
	c.Assert(err, qt.Equals, nil)
	return m
}

// AssertMacaroon asserts that the given macaroon slice is valid for the
// given operation. If id is specified then the declared identity in the
// macaroon is checked to be the same as id.
func (s *DischargeCreator) AssertMacaroon(c *qt.C, ms macaroon.Slice, op bakery.Op, id string) {
	ui, err := s.Bakery.Checker.Auth(ms).Allow(context.Background(), op)
	c.Assert(err, qt.Equals, nil)
	if id == "" {
		return
	}
	c.Assert(ui.Identity.Id(), qt.Equals, id)
}

// A VisitorFunc converts a function to a httpbakery.LegacyInteractor.
type VisitorFunc func(*url.URL) error

// LegacyInteract implements httpbakery.LegacyInteractor.LegacyInteract.
func (f VisitorFunc) LegacyInteract(ctx context.Context, _ *httpbakery.Client, _ string, u *url.URL) error {
	return f(u)
}

// A ResponseHandler is a function that is used by OpenWebBrowser to
// perform further processing with a response. A ResponseHandler should
// parse the response to determine the next action, close the body of the
// incoming response and perform queries in order to return the final
// response to the caller. The final response should not have its body
// closed.
type ResponseHandler func(*http.Client, *http.Response) (*http.Response, error)

// OpenWebBrowser returns a function that simulates opening a web browser
// to complete a login. This function only returns a non-nil error to its
// caller if there is an error initialising the client. If rh is non-nil
// it will be called with the *http.Response that was received by the
// client. This handler should arrange for any required further
// processing and return the result.
func OpenWebBrowser(c *qt.C, rh ResponseHandler) func(u *url.URL) error {
	return func(u *url.URL) error {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return errgo.Mask(err)
		}
		client := &http.Client{
			Jar: jar,
		}
		resp, err := client.Get(u.String())
		if err != nil {
			c.Logf("error getting login URL %s: %s", u.String(), err)
			return nil
		}
		if rh != nil {
			resp, err = rh(client, resp)
			if err != nil {
				c.Logf("error handling login response: %s", err)
				return nil
			}
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			buf, _ := ioutil.ReadAll(resp.Body)
			c.Logf("interaction returned error status (%s): %s", resp.Status, buf)
		}
		return nil
	}
}

// PostLoginForm returns a ResponseHandler that can be passed to
// OpenWebBrowser which will complete a login form with the given
// Username and Password, and return the result.
func PostLoginForm(username, password string) ResponseHandler {
	return func(client *http.Client, resp *http.Response) (*http.Response, error) {
		defer resp.Body.Close()
		buf, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errgo.Mask(err, errgo.Any)
		}
		// It is expected that the "login-form" template in this
		// package will have been used to generate the response.
		// This puts the "Action" (POST URL) parameter on the
		// first line by itself.
		parts := bytes.Split(buf, []byte("\n"))
		purl := string(parts[0])
		if len(purl) == 0 {
			purl = resp.Request.URL.String()
		}
		resp, err = client.PostForm(purl, url.Values{
			"username": {username},
			"password": {password},
		})
		return resp, errgo.Mask(err, errgo.Any)
	}
}

// PasswordLogin return a function that can be used with
// httpbakery.WebBrowserInteractor.OpenWebBrowser that will be configured
// to perform a username/password login using the given values.
func PasswordLogin(c *qt.C, username, password string) func(u *url.URL) error {
	return OpenWebBrowser(c, PostLoginForm(username, password))
}
