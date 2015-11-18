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
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/loggo"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/errgo.v1"
)

//go:generate httprequest-generate-client . handler client

var logger = loggo.GetLogger("meeting")

// Store defines the backing store required by a Place.
// Entries created in the store should be visible
// to all participants.
type Store interface {
	// Put associates an address with the given id.
	Put(id, address string) error

	// Get returns the address associated with the given id
	// and removes the association.
	Get(id string) (address string, err error)

	// Remove removes the entry with the given id.
	Remove(id string) error

	// RemoveOld removes entries with the given address that were created
	// earlier than the given time. It returns any ids removed.
	RemoveOld(address string, olderThan time.Time) (ids []string, err error)
}

// Place represents a meeting place for any number
// of rendezvous.
type Place struct {
	store     Store
	localAddr string
	listener  net.Listener
	handler   *handler

	mu    sync.Mutex
	items map[string]*item
}

type item struct {
	c     chan struct{}
	data0 []byte
	data1 []byte
}

// New returns a new Place that will use the given store.
// The given address should be an IP address that will
// be used to listen for requests for other servers.
// Note that this must also be sufficient for other
// servers to use to contact this one.
func New(store Store, listenAddr string) (*Place, error) {
	// TODO start garbage collection goroutine
	listener, err := net.Listen("tcp", listenAddr+":0")
	if err != nil {
		return nil, errgo.Notef(err, "cannot start listener")
	}

	p := &Place{
		store:     store,
		listener:  listener,
		localAddr: listener.Addr().String(),
		items:     make(map[string]*item),
	}
	p.handler = &handler{
		place: p,
	}
	router := httprouter.New()
	for _, h := range errMapper.Handlers(p.newHandler) {
		router.Handle(h.Method, h.Path, h.Handle)
	}
	go http.Serve(p.listener, router)
	return p, nil
}

var errMapper httprequest.ErrorMapper = func(err error) (httpStatus int, errorBody interface{}) {
	return http.StatusInternalServerError, &httprequest.RemoteError{
		Message: err.Error(),
	}
}

func newId() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", errgo.Notef(err, "cannot read random id")
	}
	return fmt.Sprintf("%x", id[:]), nil
}

func (p *Place) newHandler(httprequest.Params) (*handler, error) {
	return p.handler, nil
}

func (p *Place) Close() error {
	return p.listener.Close()
}

// NewRendezvous creates a new rendezvous holding
// the given data. The rendezvous id is returned.
func (p *Place) NewRendezvous(data []byte) (string, error) {
	id, err := newId()
	if err != nil {
		return "", errgo.Mask(err)
	}
	p.mu.Lock()
	p.items[id] = &item{
		c:     make(chan struct{}),
		data0: data,
	}
	p.mu.Unlock()
	if err := p.store.Put(id, p.localAddr); err != nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.items, id)
		return "", errgo.Notef(err, "cannot create entry for rendezvous")
	}
	return id, nil
}

func (p *Place) Wait(id string) (data0, data1 []byte, err error) {
	client, err := p.clientForId(id)
	if err != nil {
		return nil, nil, errgo.Mask(err)
	}
	resp, err := client.Wait(&waitRequest{
		Id: id,
	})
	if err != nil {
		return nil, nil, errgo.Mask(err)
	}
	return resp.Data0, resp.Data1, nil
}

func (p *Place) Done(id string, data []byte) error {
	client, err := p.clientForId(id)
	if err != nil {
		return errgo.Mask(err)
	}
	if err := client.Done(&doneRequest{
		Id: id,
		Body: doneData{
			Data1: data,
		},
	}); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

func (p *Place) clientForId(id string) (*client, error) {
	addr, err := p.store.Get(id)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &client{
		Client: httprequest.Client{
			BaseURL: "http://" + addr,
		},
	}, nil
}

// Wait waits for the rendezvous with the given id
// and returns the data provided to NewRendezvous
// and the data provided to Done.
func (p *Place) localWait(id string) (data0, data1 []byte, err error) {
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
	if err := p.store.Remove(id); err != nil {
		logger.Errorf("cannot remove rendezvous %q: %v", id, err)
	}
	return item.data0, item.data1, nil
}

// Done marks the rendezvous with the given id as complete,
// and provides it with the given data which will be
// returned from Wait.
func (p *Place) localDone(id string, data []byte) error {
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
