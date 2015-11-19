// Copyright 2014 Canonical Ltd.

// Package meeting provides a way for one thread of control
// to wait for information provided by another thread.
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

// Store defines the backing store required by the
// participants in the rendezvous.
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

	// Close closes the Store.
	Close()
}

// Server represents a rendezvous server.
type Server struct {
	getStore  func() (Store, error)
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

// Place represents a meeting place for any number
// of rendezvous.
type Place struct {
	store Store
	srv   *Server
}

// NewServer returns a new rendezvous server that listens on the given
// address. When a store is required by a server request,
// it will be acquired by calling getStore and closed after the
// request has finished.
//
// Note that listenAddr must also be sufficient for other
// servers to use to contact this one.
func NewServer(getStore func() (Store, error), listenAddr string) (*Server, error) {
	// TODO start garbage collection goroutine
	listener, err := net.Listen("tcp", listenAddr+":0")
	if err != nil {
		return nil, errgo.Notef(err, "cannot start listener")
	}

	srv := &Server{
		getStore:  getStore,
		listener:  listener,
		localAddr: listener.Addr().String(),
		items:     make(map[string]*item),
	}
	srv.handler = &handler{
		srv: srv,
	}
	router := httprouter.New()
	for _, h := range errMapper.Handlers(srv.newHandler) {
		router.Handle(h.Method, h.Path, h.Handle)
	}
	go http.Serve(srv.listener, router)
	return srv, nil
}

// Place returns a new Place that can be used to
// create and wait for rendezvous. When a store is
// required by methods on Place, the given store
// is used.
func (srv *Server) Place(store Store) *Place {
	return &Place{
		store: store,
		srv:   srv,
	}
}

// localWait is the internal version of Place.Wait.
// It only works if the given id is stored locally.
func (srv *Server) localWait(id string, store Store) (data0, data1 []byte, err error) {
	// TODO support for timeouts.

	srv.mu.Lock()
	item := srv.items[id]
	srv.mu.Unlock()
	if item == nil {
		return nil, nil, errgo.Newf("rendezvous %q not found", id)
	}
	// Wait for the channel to be closed by Done.
	<-item.c
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.items, id)
	if err := store.Remove(id); err != nil {
		logger.Errorf("cannot remove rendezvous %q: %v", id, err)
	}
	return item.data0, item.data1, nil
}

// localDone is the internal version of Place.Done.
// It only works if the given id is stored locally.
func (srv *Server) localDone(id string, data []byte) error {
	srv.mu.Lock()
	item := srv.items[id]
	defer srv.mu.Unlock()

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

func (srv *Server) newHandler(httprequest.Params) (*handler, error) {
	return srv.handler, nil
}

// Close stops the server.
func (srv *Server) Close() {
	srv.listener.Close()
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

// NewRendezvous creates a new rendezvous holding
// the given data. The rendezvous id is returned.
func (p *Place) NewRendezvous(data []byte) (string, error) {
	id, err := newId()
	if err != nil {
		return "", errgo.Mask(err)
	}
	srv := p.srv
	srv.mu.Lock()
	srv.items[id] = &item{
		c:     make(chan struct{}),
		data0: data,
	}
	srv.mu.Unlock()
	if err := p.store.Put(id, srv.localAddr); err != nil {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		delete(srv.items, id)
		return "", errgo.Notef(err, "cannot create entry for rendezvous")
	}
	return id, nil
}

// Wait waits for the rendezvous with the given id
// and returns the data provided to NewRendezvous
// and the data provided to Done.
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

// Done marks the rendezvous with the given id as complete,
// and provides it with the given data which will be
// returned from Wait.
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
