// Copyright 2015 Canonical Ltd.

// +build go1.3

// Package mempool implements a version of sync.Pool
// as supported in Go versions later than 1.2.
// Under Go 1.3 or later, it uses the native sync.Pool.
//
package mempool

import "sync"

// Pool wraps sync.Pool for portability purposes.
type Pool sync.Pool

func (p *Pool) Get() interface{} {
	return (*sync.Pool)(p).Get()
}

func (p *Pool) Put(v interface{}) {
	(*sync.Pool)(p).Put(v)
}
