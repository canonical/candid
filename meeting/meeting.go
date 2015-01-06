// Copyright 2014 Canonical Ltd.

// Package meeting provides a way for one thread of control
// to wait for information provided by another thread.
//
// Currently the threads must be on the same server, but
// this is an implementation restriction that will be lifted.
package meeting

import (
	"crypto/rand"
	"fmt"
	"sync"

	"gopkg.in/errgo.v1"
)

// Place represents a meeting place for any number
// of rendezvous.
type Place struct {
	mu    sync.Mutex
	items map[string]*item
}

type item struct {
	c     chan struct{}
	data0 []byte
	data1 []byte
}

// New returns a new Place.
func New() *Place {
	return &Place{
		items: make(map[string]*item),
	}
}

func newId() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", errgo.Notef(err, "cannot read random id")
	}
	return fmt.Sprintf("%x", id[:]), nil
}

// NewRendezvous creates a new rendezvous holding
// the given data. The rendezvous id is returned.
func (p *Place) NewRendezvous(data []byte) (string, error) {
	id, err := newId()
	if err != nil {
		return "", errgo.Mask(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.items[id] = &item{
		c:     make(chan struct{}),
		data0: data,
	}
	return id, nil
}

// Wait waits for the rendezvous with the given id
// and returns the data provided to NewRendezvous
// and the data provided to Done.
func (p *Place) Wait(id string) (data0, data1 []byte, err error) {
	// TODO support for timeouts.

	p.mu.Lock()
	item := p.items[id]
	p.mu.Unlock()
	if item == nil {
		return nil, nil, errgo.Newf("rendezvous %q not found", id)
	}
	// Wait for the channel to be closed by Done.
	<-item.c
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.items, id)
	return item.data0, item.data1, nil
}

// Done marks the rendezvous with the given id as complete,
// and provides it with the given data which will be
// returned from Wait.
func (p *Place) Done(id string, data []byte) error {
	p.mu.Lock()
	item := p.items[id]
	defer p.mu.Unlock()

	if item == nil {
		return errgo.Newf("rendezvous %q not found", id)
	}
	select {
	case <-item.c:
		return errgo.Newf("rendezvous %q done twice", id)
	default:
		item.data1 = data
		close(item.c)
	}
	return nil
}
