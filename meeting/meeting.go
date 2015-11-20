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
	"gopkg.in/tomb.v2"
)

//go:generate httprequest-generate-client . handler client

var logger = loggo.GetLogger("meeting")

var (
	// pollInterval holds the interval at which the
	// garbage collector goroutine polls for expired
	// rendezvous.
	pollInterval = 30 * time.Second

	// expiryDuration holds the length of time that we keep
	// a rendezvous around before deleting it. This needs to
	// be long enough that the user can do all the web page
	// interaction that they need to before the rendezvous is
	// completed.
	expiryDuration = time.Hour

	// reallyOldExpiryDuration holds the length of time after
	// which we'll delete rendezvous regardless of server.
	// This caters for the case where a given server has restarted
	// without removing its existing entries.
	reallyOldExpiryDuration = 7 * 24 * time.Hour
)

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
	// It should not return an error if the entry has already
	// been removed.
	Remove(id string) error

	// RemoveOld removes entries with the given address that were created
	// earlier than the given time. It returns any ids removed.
	// If it encountered an error while deleting the ids, it
	// may return a non-empty ids slice and a non-nil error.
	RemoveOld(address string, olderThan time.Time) (ids []string, err error)

	// Close closes the Store.
	Close()
}

// Server represents a rendezvous server.
type Server struct {
	tomb      tomb.Tomb
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
	return newServer(getStore, listenAddr, true)
}

func newServer(getStore func() (Store, error), listenAddr string, runGC bool) (*Server, error) {
	// TODO start garbage collection goroutine
	listener, err := net.Listen("tcp", net.JoinHostPort(listenAddr, "0"))
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
	if runGC {
		srv.tomb.Go(srv.gc)
	}
	srv.tomb.Go(func() error {
		http.Serve(srv.listener, router)
		return nil
	})
	return srv, nil
}

// Close stops the server.
func (srv *Server) Close() {
	srv.listener.Close()
	srv.tomb.Kill(nil)
	srv.tomb.Wait()
}

// gc garbage collects expired rendezvous by polling occasionally.
func (srv *Server) gc() error {
	dying := false
	for {
		err := srv.runGC(dying, time.Now())
		if err != nil {
			logger.Errorf("meeting GC: %v", err)
		}
		if dying {
			return nil
		}
		// We wait at the end of the loop rather than the start
		// so we are always guaranteed a GC when the server starts
		// up.
		select {
		case <-time.After(pollInterval):
		case <-srv.tomb.Dying():
			dying = true
		}
	}
}

// runGC runs a single garbage collection at the given time.
// If dying is true, it removes all entries in the server.
func (srv *Server) runGC(dying bool, now time.Time) error {
	store, err := srv.getStore()
	if err != nil {
		return errgo.Notef(err, "cannot get Store")
	}
	defer store.Close()

	var expiryTime time.Time
	if dying {
		// A little bit in the future so that we're sure to
		// find all entries.
		expiryTime = now.Add(time.Millisecond)
	} else {
		expiryTime = now.Add(-expiryDuration)
	}
	ids, err := store.RemoveOld(srv.localAddr, expiryTime)
	if len(ids) > 0 {
		srv.mu.Lock()
		for _, id := range ids {
			delete(srv.items, id)
		}
		srv.mu.Unlock()
	}
	if err != nil {
		return errgo.Notef(err, "cannot remove old entries")
	}
	_, err = store.RemoveOld("", time.Now().Add(-reallyOldExpiryDuration))
	if err != nil {
		return errgo.Notef(err, "cannot remove really old entries")
	}
	return nil
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
	srv.mu.Lock()
	item := srv.items[id]
	srv.mu.Unlock()
	if item == nil {
		return nil, nil, errgo.Newf("rendezvous %q not found", id)
	}
	// Wait for the channel to be closed by Done.
	expired := false
	select {
	case <-item.c:
	case <-time.After(expiryDuration):
		expired = true
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.items, id)
	if err := store.Remove(id); err != nil {
		logger.Errorf("cannot remove rendezvous %q: %v", id, err)
	}
	if expired {
		return nil, nil, errgo.Newf("rendezvous has expired after %v", expiryDuration)
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
