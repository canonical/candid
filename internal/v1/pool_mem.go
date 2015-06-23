// Copyright 2015 Canonical Ltd.

// +build !go1.3

package v1

import "github.com/CanonicalLtd/blues-identity/internal/mempool"

func newPool(f func() interface{}) pool {
	return &mempool.Pool{
		New: f,
	}
}
