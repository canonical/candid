// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package ussologin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	qt "github.com/frankban/quicktest"
	jt "github.com/juju/testing"
	"github.com/juju/usso"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/juju/environschema.v1/form"

	"github.com/canonical/candid/v2/candidclient/ussologin"
)

func TestPutGetToken(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	token := &usso.SSOData{
		ConsumerKey:    "consumerkey",
		ConsumerSecret: "consumersecret",
		Realm:          "realm",
		TokenKey:       "tokenkey",
		TokenName:      "tokenname",
		TokenSecret:    "tokensecret",
	}
	path := filepath.Join(c.Mkdir(), "subdir", "tokenFile")
	store := ussologin.NewFileTokenStore(path)
	err := store.Put(token)
	c.Assert(err, qt.IsNil)

	tok, err := store.Get()
	c.Assert(err, qt.IsNil)
	c.Assert(tok, qt.DeepEquals, token)
	data, err := ioutil.ReadFile(path)
	c.Assert(err, qt.IsNil)
	var storedToken *usso.SSOData
	err = json.Unmarshal(data, &storedToken)
	c.Assert(err, qt.IsNil)
	c.Assert(token, qt.DeepEquals, storedToken)
}

func TestReadInvalidToken(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	path := fmt.Sprintf("%s/tokenFile", c.Mkdir())
	err := ioutil.WriteFile(path, []byte("foobar"), 0700)
	c.Assert(err, qt.IsNil)
	store := ussologin.NewFileTokenStore(path)

	_, err = store.Get()
	c.Assert(err, qt.ErrorMatches, `cannot unmarshal token: invalid character 'o' in literal false \(expecting 'a'\)`)
}

func TestTokenInStore(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	testToken := &usso.SSOData{
		ConsumerKey:    "consumerkey",
		ConsumerSecret: "consumersecret",
		Realm:          "realm",
		TokenKey:       "tokenkey",
		TokenName:      "tokenname",
		TokenSecret:    "tokensecret",
	}
	st := &testTokenStore{
		tok: testToken,
	}
	g := &ussologin.StoreTokenGetter{
		Store: st,
	}
	ctx := context.Background()
	tok, err := g.GetToken(ctx)
	c.Assert(err, qt.IsNil)
	c.Assert(tok, qt.DeepEquals, testToken)
	c.Assert(st.Calls(), qt.DeepEquals, []jt.StubCall{{
		FuncName: "Get",
	}})
}

func TestTokenNotInStore(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	testToken := &usso.SSOData{
		ConsumerKey:    "consumerkey",
		ConsumerSecret: "consumersecret",
		Realm:          "realm",
		TokenKey:       "tokenkey",
		TokenName:      "tokenname",
		TokenSecret:    "tokensecret",
	}
	st := &testTokenStore{}
	st.SetErrors(errgo.New("not found"))
	fg := &testTokenGetter{
		tok: testToken,
	}
	g := &ussologin.StoreTokenGetter{
		Store:       st,
		TokenGetter: fg,
	}
	ctx := context.Background()
	tok, err := g.GetToken(ctx)
	c.Assert(err, qt.IsNil)
	c.Assert(tok, qt.DeepEquals, testToken)
	c.Assert(st.Calls(), qt.DeepEquals, []jt.StubCall{{
		FuncName: "Get",
	}, {
		FuncName: "Put",
		Args:     []interface{}{testToken},
	}})
	c.Assert(fg.Calls(), qt.DeepEquals, []jt.StubCall{{
		FuncName: "GetToken",
		Args:     []interface{}{ctx},
	}})
}

func TestCorrectUserPasswordSentToUSSOServer(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	ussoStub := &ussoServerStub{}
	c.Patch(ussologin.Server, ussoStub)
	tg := ussologin.FormTokenGetter{
		Filler: &testFiller{
			map[string]interface{}{
				ussologin.UserKey: "foobar",
				ussologin.PassKey: "pass",
				ussologin.OTPKey:  "1234",
			}},
		Name: "testToken",
	}
	_, err := tg.GetToken(context.Background())
	c.Assert(err, qt.IsNil)
	calls := ussoStub.Calls()
	c.Assert(len(calls) > 0, qt.Equals, true)
	c.Assert(calls[0], qt.DeepEquals, jt.StubCall{
		FuncName: "GetTokenWithOTP",
		Args:     []interface{}{"foobar", "pass", "1234", "testToken"},
	})
}

func TestLoginFailsToGetToken(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	ussoStub := &ussoServerStub{}
	ussoStub.SetErrors(errgo.New("something failed"))
	c.Patch(ussologin.Server, ussoStub)
	tg := ussologin.FormTokenGetter{
		Filler: &testFiller{
			map[string]interface{}{
				ussologin.UserKey: "foobar",
				ussologin.PassKey: "pass",
				ussologin.OTPKey:  "1234",
			}},
		Name: "testToken",
	}
	_, err := tg.GetToken(context.Background())
	c.Assert(err, qt.ErrorMatches, "cannot get token: something failed")
}

func TestFailedToReadLoginParameters(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	ussoStub := &ussoServerStub{}
	c.Patch(ussologin.Server, ussoStub)
	tg := ussologin.FormTokenGetter{
		Filler: &errFiller{},
	}
	_, err := tg.GetToken(context.Background())
	c.Assert(err, qt.ErrorMatches, "cannot read login parameters: something failed")
	c.Assert(ussoStub.Calls(), qt.HasLen, 0)
}

type testFiller struct {
	form map[string]interface{}
}

func (t *testFiller) Fill(f form.Form) (map[string]interface{}, error) {
	return t.form, nil
}

type errFiller struct{}

func (t *errFiller) Fill(f form.Form) (map[string]interface{}, error) {
	return nil, errgo.New("something failed")
}

type ussoServerStub struct {
	jt.Stub
}

func (u *ussoServerStub) GetTokenWithOTP(email, password, otp, tokenName string) (*usso.SSOData, error) {
	u.AddCall("GetTokenWithOTP", email, password, otp, tokenName)
	return &usso.SSOData{}, u.NextErr()
}

type testTokenGetter struct {
	jt.Stub
	tok *usso.SSOData
}

func (g *testTokenGetter) GetToken(ctx context.Context) (*usso.SSOData, error) {
	g.MethodCall(g, "GetToken", ctx)
	return g.tok, g.NextErr()
}

type testTokenStore struct {
	jt.Stub
	tok *usso.SSOData
}

func (m *testTokenStore) Put(tok *usso.SSOData) error {
	m.MethodCall(m, "Put", tok)
	m.tok = tok
	return m.NextErr()
}

func (m *testTokenStore) Get() (*usso.SSOData, error) {
	m.MethodCall(m, "Get")
	return m.tok, m.NextErr()
}
