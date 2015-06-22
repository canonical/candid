// Copyright 2015 Canonical Ltd.

// +build go1.3

package v1

import "sync"

func newPool(f func() interface{}) pool {
	return &sync.Pool{
		New: f,
	}
}
