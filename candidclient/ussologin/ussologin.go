// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

// Package ussologin defines functionality used for allowing clients
// to authenticate with the Candid server using USSO OAuth.
package ussologin

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/juju/usso"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/environschema.v1"
	"gopkg.in/juju/environschema.v1/form"
)

type tokenGetter interface {
	GetTokenWithOTP(username, password, otp, tokenName string) (*usso.SSOData, error)
}

// This is defined here to allow it to be stubbed out in tests
var server tokenGetter = usso.ProductionUbuntuSSOServer

var (
	userKey = "E-Mail"
	passKey = "Password"
	otpKey  = "Two-factor auth (Enter for none)"
)

// A FormTokenGetter is a TokenGetter implementation that presents a form
// to the user to get login details, and then uses those to get a token
// from Ubuntu SSO.
type FormTokenGetter struct {
	Filler form.Filler
	Name   string
}

// GetToken uses filler to interact with the user and uses the provided
// information to obtain an OAuth token from Ubuntu SSO. The returned
// token can subsequently be used with LoginWithToken to perform a login.
// The tokenName argument is used as the name of the generated token in
// Ubuntu SSO. If Ubuntu SSO returned an error when trying to retrieve
// the token the error will have a cause of type *usso.Error.
func (g FormTokenGetter) GetToken(ctx context.Context) (*usso.SSOData, error) {
	if g.Name == "" {
		g.Name = "candidclient"
	}
	login, err := g.Filler.Fill(loginForm)
	if err != nil {
		return nil, errgo.Notef(err, "cannot read login parameters")
	}
	tok, err := server.GetTokenWithOTP(
		login[userKey].(string),
		login[passKey].(string),
		login[otpKey].(string),
		g.Name,
	)

	if err != nil {
		return nil, errgo.NoteMask(err, "cannot get token", isUSSOError)
	}
	return tok, nil
}

// loginForm contains the fields required for login.
var loginForm = form.Form{
	Title: "Login to Ubuntu SSO",
	Fields: environschema.Fields{
		userKey: environschema.Attr{
			Description: "Username",
			Type:        environschema.Tstring,
			Mandatory:   true,
			Group:       "1",
		},
		passKey: environschema.Attr{
			Description: "Password",
			Type:        environschema.Tstring,
			Mandatory:   true,
			Secret:      true,
			Group:       "1",
		},
		otpKey: environschema.Attr{
			Description: "Two-factor auth",
			Type:        environschema.Tstring,
			Mandatory:   true,
			Group:       "2",
		},
	},
}

// A TokenGetter is used to fetch a Ubuntu SSO OAuth token.
type TokenGetter interface {
	GetToken(context.Context) (*usso.SSOData, error)
}

// A StoreTokenGetter is a TokenGetter that will try to retrieve the
// token from some storage, before falling back to another TokenGetter.
// If the fallback TokenGetter sucessfully retrieves a token then that
// token will be put in the store.
type StoreTokenGetter struct {
	Store       TokenStore
	TokenGetter TokenGetter
}

// GetToken implements TokenGetter.GetToken. A token is first attmepted
// to retireve from the store. If a stored token is not available then
// GetToken will fallback to TokenGetter.GetToken (if configured).
func (g StoreTokenGetter) GetToken(ctx context.Context) (*usso.SSOData, error) {
	tok, err := g.Store.Get()
	if err == nil {
		return tok, nil
	}
	if g.TokenGetter == nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	tok, err = g.TokenGetter.GetToken(ctx)
	if err == nil {
		// Ignore any errors storing the token, the user will
		// just have to get it again next time.
		g.Store.Put(tok)
	}
	return tok, errgo.Mask(err, errgo.Any)
}

// TokenStore defines the interface for something that can store and
// returns oauth tokens.
type TokenStore interface {
	// Put stores an Ubuntu SSO OAuth token.
	Put(tok *usso.SSOData) error
	// Get returns an Ubuntu SSO OAuth token from store
	Get() (*usso.SSOData, error)
}

// FileTokenStore implements the TokenStore interface by storing the
// JSON-encoded oauth token in a file.
type FileTokenStore struct {
	path string
}

// NewFileTokenStore returns a new FileTokenStore
// that uses the given path for storage.
func NewFileTokenStore(path string) *FileTokenStore {
	return &FileTokenStore{path}
}

// Put implements TokenStore.Put by writing the token to the
// FileTokenStore's file. If the file doesn't exist it will be created,
// including any required directories.
func (f *FileTokenStore) Put(tok *usso.SSOData) error {
	data, err := json.Marshal(tok)
	if err != nil {
		return errgo.Notef(err, "cannot marshal token")
	}
	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errgo.Notef(err, "cannot create directory %q", dir)
	}
	if err := ioutil.WriteFile(f.path, data, 0600); err != nil {
		return errgo.Notef(err, "cannot write file")
	}
	return nil
}

// Get implements TokenStore.Get by
// reading the token from the FileTokenStore's file.
func (f *FileTokenStore) Get() (*usso.SSOData, error) {
	data, err := ioutil.ReadFile(f.path)
	if err != nil {
		return nil, errgo.Notef(err, "cannot read token")
	}
	var tok usso.SSOData
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, errgo.Notef(err, "cannot unmarshal token")
	}
	return &tok, nil
}

// isUSSOError determines if err represents an error of type *usso.Error.
func isUSSOError(err error) bool {
	_, ok := err.(*usso.Error)
	return ok
}
