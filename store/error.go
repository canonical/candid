// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package store

import (
	"fmt"

	errgo "gopkg.in/errgo.v1"
)

var (
	// ErrNotFound is the error cause used when an identity cannot be
	// found in storage.
	ErrNotFound = errgo.New("not found")

	// ErrDuplicateUsername is the error cause used when an update
	// attempts to set a username that is already in use.
	ErrDuplicateUsername = errgo.New("duplicate username")

	// ErrDuplicateKey is the error cause used when trying to set a
	// new key in a KeyValueStore where the key already exists.
	ErrDuplicateKey = errgo.New("duplicate key")
)

// NotFoundError creates a new error with a cause of ErrNotFound and an
// appropriate message.
func NotFoundError(id string, providerID ProviderIdentity, username string) error {
	msg := "identity not specified"
	switch {
	case id != "":
		msg = fmt.Sprintf("identity %q not found", id)
	case providerID != "":
		msg = fmt.Sprintf("identity %q not found", providerID)
	case username != "":
		msg = fmt.Sprintf("user %s not found", username)
	}
	err := errgo.WithCausef(nil, ErrNotFound, msg)
	err.(*errgo.Err).SetLocation(1)
	return err
}

// DuplicateUsernameError creates a new error with a cause of
// ErrDuplicateUsername and an appropriate message.
func DuplicateUsernameError(username string) error {
	err := errgo.WithCausef(nil, ErrDuplicateUsername, "username %s already in use", username)
	err.(*errgo.Err).SetLocation(1)
	return err
}

// KeyNotFoundError creates a new error with a cause of ErrNotFound and
// an appropriate message.
func KeyNotFoundError(key string) error {
	err := errgo.WithCausef(nil, ErrNotFound, "key %s not found", key)
	err.(*errgo.Err).SetLocation(1)
	return err
}

// DuplicateKeyError creates a new error with a cause of ErrDuplicateKey
// and an appropriate message.
func DuplicateKeyError(key string) error {
	err := errgo.WithCausef(nil, ErrDuplicateKey, "key %s already exists", key)
	err.(*errgo.Err).SetLocation(1)
	return err
}
