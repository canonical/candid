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
	"github.com/juju/utils/clock"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/context"
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

	// defaultExpiryDuration holds the length of time that we keep
	// a rendezvous around before deleting it. This needs to
	// be long enough that the user can do all the web page
	// interaction that they need to before the rendezvous is
	// completed.
	defaultExpiryDuration = time.Hour

	// defaultWaitTimeout holds the default maximum
	// length of time that a wait request can block for.
	defaultWaitTimeout = time.Minute

	// reallyOldExpiryDuration holds the length of time after
	// which we'll delete rendezvous regardless of server.
	// This caters for the case where a given server has restarted
	// without removing its existing entries.
	reallyOldExpiryDuration = 7 * 24 * time.Hour

	// Clock holds the clock implementation used by the meeting package.
	// This is exported so it can be changed for testing purposes.
	Clock clock.Clock = clock.WallClock
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
	Remove(id string) (time.Time, error)

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
	tomb           tomb.Tomb
	getStore       func() Store
	localAddr      string
	listener       net.Listener
	handler        *handler
	metrics        Metrics
	waitTimeout    time.Duration
	expiryDuration time.Duration

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

// Metrics represents a way to report metrics information
// about the meeting service. It must be callable
// concurrently.
type Metrics interface {
	// RequestCompleted is called every time an HTTP
	// request has completed with the time the request started.
	RequestCompleted(startTime time.Time)

	// RequestsExpired is called when some requests
	// have been garbage collected with the number
	// of GC'd requests.
	RequestsExpired(count int)
}

// Params holds parameters for the NewServer function.
type Params struct {
	// GetStore is used to acquire store instances.
	// When a store is required by a server request,
	// it will be acquired by calling getStore and closed after the
	// request has finished.
	GetStore func() Store

	// Metrics holds an object that's used to report server metrics.
	// If it's nil, no metrics will be reported.
	Metrics Metrics

	// ListenAddr holds the host name to listen on. This
	// should not have a port number.
	// Note that listenAddr must also be sufficient for other
	// servers to use to contact this one.
	ListenAddr string

	// DisableGC holds whether the garbage collector is disabled.
	DisableGC bool

	// WaitTimeout holds the maximum time to that
	// wait requests will wait. If it is zero, a default
	// duration will be used.
	WaitTimeout time.Duration

	// ExpiryDuration holds the maximum amount of time
	// a rendezvous will be kept around for. If it is zero, a default
	// duration will be used.
	ExpiryDuration time.Duration
}

// NewServer returns a new rendezvous server using the given
// parameters.
func NewServer(p Params) (*Server, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(p.ListenAddr, "0"))
	if err != nil {
		return nil, errgo.Notef(err, "cannot start listener")
	}
	if p.Metrics == nil {
		p.Metrics = noMetrics{}
	}
	if p.WaitTimeout == 0 {
		p.WaitTimeout = defaultWaitTimeout
	}
	if p.ExpiryDuration == 0 {
		p.ExpiryDuration = defaultExpiryDuration
	}
	srv := &Server{
		getStore:       p.GetStore,
		listener:       listener,
		localAddr:      listener.Addr().String(),
		items:          make(map[string]*item),
		metrics:        p.Metrics,
		waitTimeout:    p.WaitTimeout,
		expiryDuration: p.ExpiryDuration,
	}
	srv.handler = &handler{
		srv: srv,
	}
	router := httprouter.New()
	for _, h := range reqServer.Handlers(srv.newHandler) {
		router.Handle(h.Method, h.Path, h.Handle)
	}
	if !p.DisableGC {
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
		err := srv.runGC(dying, Clock.Now())
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
		case <-Clock.After(pollInterval):
		case <-srv.tomb.Dying():
			dying = true
		}
	}
}

// runGC runs a single garbage collection at the given time.
// If dying is true, it removes all entries in the server.
func (srv *Server) runGC(dying bool, now time.Time) error {
	store := srv.getStore()
	defer store.Close()

	var expiryTime time.Time
	if dying {
		// A little bit in the future so that we're sure to
		// find all entries.
		expiryTime = now.Add(time.Millisecond)
	} else {
		expiryTime = now.Add(-srv.expiryDuration)
	}
	ids, err := store.RemoveOld(srv.localAddr, expiryTime)
	if len(ids) > 0 {
		srv.mu.Lock()
		for _, id := range ids {
			delete(srv.items, id)
		}
		srv.mu.Unlock()
		srv.metrics.RequestsExpired(len(ids))
	}
	if err != nil {
		return errgo.Notef(err, "cannot remove old entries")
	}
	ids, err = store.RemoveOld("", now.Add(-reallyOldExpiryDuration))
	if err != nil {
		return errgo.Notef(err, "cannot remove really old entries")
	}
	if len(ids) > 0 {
		srv.metrics.RequestsExpired(len(ids))
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
func (srv *Server) localWait(id string, getStore func() Store) (data0, data1 []byte, err error) {
	srv.mu.Lock()
	item := srv.items[id]
	srv.mu.Unlock()
	if item == nil {
		return nil, nil, errgo.Newf("rendezvous %q not found", id)
	}
	// Wait for the channel to be closed by Done.
	timeout := false
	select {
	case <-item.c:
	case <-Clock.After(srv.waitTimeout):
		timeout = true
	}
	// Note that we get the Store *after* waiting, so we
	// don't tie up resources while waiting.
	store := getStore()
	defer store.Close()
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.items, id)
	t, err := store.Remove(id)
	if err != nil {
		logger.Errorf("cannot remove rendezvous %q: %v", id, err)
	}
	if !t.IsZero() {
		srv.metrics.RequestCompleted(t)
	}
	if timeout {
		return nil, nil, errgo.Newf("rendezvous timed out after %v", srv.waitTimeout)
	}
	return item.data0, item.data1, nil
}

// localDone is the internal version of Place.Done.
// It only works if the given id is stored locally.
func (srv *Server) localDone(id string, data []byte) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	item := srv.items[id]

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

func (srv *Server) isLocal(id string) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.items[id] != nil
}

func (srv *Server) newHandler(p httprequest.Params) (*handler, context.Context, error) {
	return srv.handler, p.Context, nil
}

var reqServer = httprequest.Server{
	ErrorMapper: func(ctx context.Context, err error) (httpStatus int, errorBody interface{}) {
		return http.StatusInternalServerError, &httprequest.RemoteError{
			Message: err.Error(),
		}
	},
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
	if p.srv.isLocal(id) {
		return p.srv.localWait(id, func() Store {
			// Note that the Place doesn't close its store,
			// so neither should localWait.
			return storeNopCloser{p.store}
		})
	}
	client, err := p.clientForId(id)
	if err != nil {
		return nil, nil, errgo.Mask(err)
	}
	resp, err := client.Wait(context.TODO(), &waitRequest{
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
	if p.srv.isLocal(id) {
		return p.srv.localDone(id, data)
	}
	client, err := p.clientForId(id)
	if err != nil {
		return errgo.Mask(err)
	}
	if err := client.Done(context.TODO(), &doneRequest{
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

type storeNopCloser struct {
	Store
}

func (storeNopCloser) Close() {
}

// noMetrics implements Metrics by doing nothing.
type noMetrics struct{}

func (noMetrics) RequestCompleted(startTime time.Time) {}

func (noMetrics) RequestsExpired(count int) {}
