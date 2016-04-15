// Copyright 2015 Canonical Ltd.

// Package limitpool provides functionality for limiting the
// total number of items in use at any one time (for example
// to limit the number of MongoDB sessions).
package limitpool

import (
	"errors"
	"sync"
	"time"
)

// ErrLimitExceeded is the error returned when the pool cannot retrieve
// an item because too many are currently in use.
var ErrLimitExceeded = errors.New("pool limit exceeded")

// ErrClosed is the error returned when the pool cannot retrieve
// an item because the pool has been closed.
var ErrClosed = errors.New("pool closed")

// Pool holds a pool of items and keeps track of the
// total number of allocated items.
type Pool struct {
	limit int

	// new is called to create new instances of pool objects.
	new func() Item

	// c is a buffered channel holding any
	// values in the pool that are not currently
	// in use.
	c chan Item

	// mu guards the fields below it.
	mu sync.Mutex

	// n holds the current number of allocated items.
	n int

	// a holds current number of available items.
	a int

	// closed holds whether the pool has been closed.
	closed bool
}

// Item represents an object that can be managed by the pool.
type Item interface {
	Close()
}

// NewPool returns a new pool that imposes the given limit
// on the total number of allocated items.
//
// When a new item is required, new will be called to create it.
func NewPool(limit int, new func() Item) *Pool {
	return &Pool{
		limit: limit,
		new:   new,
		c:     make(chan Item, limit),
	}
}

// Close marks the pool as closed and closes all of the items in the
// pool.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	close(p.c)
	for v := range p.c {
		p.n--
		v.Close()
	}
}

// Get retrieves an item from the pool. If the pool is currently empty
// and fewer than limit items are currently in circulation a new one will
// be created. If the limit has been reached then Get will wait for at
// least t before returng ErrLimitExceeded.
func (p *Pool) Get(t time.Duration) (Item, error) {
	v, err := p.get(false)
	if err == ErrLimitExceeded {
		select {
		case v, ok := <-p.c:
			if !ok {
				return nil, ErrClosed
			}
			return v, nil
		case <-time.After(t):
		}
	}
	return v, err
}

func (p *Pool) get(noLimit bool) (Item, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		if !noLimit {
			return nil, ErrClosed
		}
		p.n++
		return p.new(), nil
	}
	select {
	case v := <-p.c:
		p.a--
		return v, nil
	default:
	}
	if noLimit || p.n < p.limit {
		p.n++
		return p.new(), nil
	}
	return nil, ErrLimitExceeded
}

// GetNoLimit retrieve an item from the pool if one is available,
// otherwise it creates one immediately and returns it.
func (p *Pool) GetNoLimit() Item {
	v, err := p.get(true)
	if err != nil {
		// This should not be possible.
		panic(err)
	}
	return v
}

// Add records that an item has been created outside
// the pool, adding one to the current pool count,
// as if Get had been called, but without invoking the
// new function.
func (p *Pool) Add() {
	p.mu.Lock()
	p.n++
	p.mu.Unlock()
}

// Put puts v back into the pool. The item must previously have been
// returned from Get or GetNoLimit, or had its existence recorded with
// Add.
//
// If the number of allocated items exceeds the limit, x will be
// immediately closed.
func (p *Pool) Put(v Item) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.n > p.limit {
		p.n--
		v.Close()
		return
	}
	select {
	case p.c <- v:
		p.a++
		return
	default:
	}
	// This should be impossible (if n <= max then there must be room in the channel)
	// but it can be recovered by deleting.
	p.n--
	v.Close()
}

// Limit returns the limit of items in the pool.
func (p *Pool) Limit() int {
	return p.limit
}

// Size returns the total number of items in the pool.
func (p *Pool) Size() int {
	return p.n
}

// Free returns the number of unused items in the pool.
func (p *Pool) Free() int {
	return p.a
}

// Info is the interface which wraps limit pool information.
type Info interface {
	// Limit returns the limit of items in the pool.
	Limit() int
	// Size returns the total number of items in the pool.
	Size() int
	// Free returns the number of unused items in the pool.
	Free() int
}
