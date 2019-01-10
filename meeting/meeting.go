// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package meeting provides a way for one thread of control
// to wait for information provided by another thread.
package meeting

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/juju/clock"
	"github.com/juju/loggo"
	"github.com/juju/utils"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/tomb.v2"
)

//go:generate httprequest-generate-client . handler client

var logger = loggo.GetLogger("candid.meeting")

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
	// Context returns a context that is suitable for passing to the
	// other store methods. Store methods called with such a context
	// will be sequentially consistent; for example, a value that is
	// Put will immediately be available from a Get method.
	//
	// The returned close function must be called when the returned
	// context will no longer be used, to allow for any required
	// cleanup.
	Context(ctx context.Context) (_ context.Context, close func())

	// Put associates an address with the given id.
	Put(ctx context.Context, id, address string) error

	// Get returns the address associated with the given id
	// and removes the association.
	Get(ctx context.Context, id string) (address string, err error)

	// Remove removes the entry with the given id.
	// It should not return an error if the entry has already
	// been removed.
	Remove(ctx context.Context, id string) (time.Time, error)

	// RemoveOld removes entries with the given address that were created
	// earlier than the given time. It returns any ids removed.
	// If it encountered an error while deleting the ids, it
	// may return a non-empty ids slice and a non-nil error.
	RemoveOld(ctx context.Context, address string, olderThan time.Time) (ids []string, err error)
}

// Place represents a rendezvous place.
type Place struct {
	tomb           tomb.Tomb
	store          Store
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
	created time.Time
	c       chan struct{}
	data0   []byte
	data1   []byte
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
	// Store is used for storage of persistent data.
	Store Store

	// Metrics holds an object that's used to report server metrics.
	// If it's nil, no metrics will be reported.
	Metrics Metrics

	// ListenAddr holds the host name to listen on. This
	// should not have a port number.
	// Note that ListenAddr must also be sufficient for other
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

// NewServer returns a new rendezvous place using the given
// parameters.
func NewPlace(params Params) (*Place, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(params.ListenAddr, "0"))
	if err != nil {
		return nil, errgo.Notef(err, "cannot start listener")
	}
	if params.Metrics == nil {
		params.Metrics = noMetrics{}
	}
	if params.WaitTimeout == 0 {
		params.WaitTimeout = defaultWaitTimeout
	}
	if params.ExpiryDuration == 0 {
		params.ExpiryDuration = defaultExpiryDuration
	}
	p := &Place{
		store:          params.Store,
		listener:       listener,
		localAddr:      listener.Addr().String(),
		items:          make(map[string]*item),
		metrics:        params.Metrics,
		waitTimeout:    params.WaitTimeout,
		expiryDuration: params.ExpiryDuration,
	}
	p.handler = &handler{
		place: p,
	}
	router := httprouter.New()
	for _, h := range reqServer.Handlers(p.newHandler) {
		router.Handle(h.Method, h.Path, h.Handle)
	}
	if !params.DisableGC {
		p.tomb.Go(p.gc)
	}
	p.tomb.Go(func() error {
		http.Serve(p.listener, router)
		return nil
	})
	return p, nil
}

// Close shuts down the rendezvous place.
func (p *Place) Close() {
	p.listener.Close()
	p.tomb.Kill(nil)
	p.tomb.Wait()
}

// gc garbage collects expired rendezvous by polling occasionally.
func (p *Place) gc() error {
	dying := false
	for {
		ctx, close := p.store.Context(context.Background())
		err := p.runGC(ctx, dying, Clock.Now())
		close()
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
		case <-p.tomb.Dying():
			dying = true
		}
	}
}

// runGC runs a single garbage collection at the given time.
// If dying is true, it removes all entries in the server.
func (p *Place) runGC(ctx context.Context, dying bool, now time.Time) error {
	var expiryTime time.Time
	if dying {
		// A little bit in the future so that we're sure to
		// find all entries.
		expiryTime = now.Add(time.Millisecond)
	} else {
		expiryTime = now.Add(-p.expiryDuration)
	}
	ids, err := p.store.RemoveOld(ctx, p.localAddr, expiryTime)
	if len(ids) > 0 {
		p.mu.Lock()
		for _, id := range ids {
			delete(p.items, id)
		}
		p.mu.Unlock()
		p.metrics.RequestsExpired(len(ids))
	}
	if err != nil {
		return errgo.Notef(err, "cannot remove old entries")
	}
	ids, err = p.store.RemoveOld(ctx, "", now.Add(-reallyOldExpiryDuration))
	if err != nil {
		return errgo.Notef(err, "cannot remove really old entries")
	}
	if len(ids) > 0 {
		p.metrics.RequestsExpired(len(ids))
	}
	return nil
}

// localWait is the internal version of Place.Wait.
// It only works if the given id is stored locally.
func (p *Place) localWait(ctx context.Context, id string) (data0, data1 []byte, err error) {
	logger.Infof("localWait %q", id)
	p.mu.Lock()
	item := p.items[id]
	p.mu.Unlock()
	if item == nil {
		return nil, nil, errgo.Newf("rendezvous %q not found", id)
	}
	now := Clock.Now()
	expiryDeadline := item.created.Add(p.expiryDuration)
	deadline := expiryDeadline
	if t := now.Add(p.waitTimeout); t.Before(deadline) {
		deadline = t
	}
	logger.Infof("timeout %v", deadline.Sub(now))
	ctx, cancel := utils.ContextWithTimeout(ctx, Clock, deadline.Sub(now))
	defer cancel()
	// Wait for the channel to be closed by Done or for the overall
	// expiry deadline or the wait to pass, whichever comes first.
	var expiredErr error
	select {
	case <-item.c:
	case <-ctx.Done():
		expiredErr = ctx.Err()
	}
	removed := false
	if expiredErr == nil || Clock.Now().After(expiryDeadline) {
		// The client has acquired the rendezvous OK or the full
		// expiry duration has elapsed, so remove the item. Note
		// that we're getting the Store *after* waiting, so we
		// don't tie up resources while waiting.
		ctx, close := p.store.Context(ctx)
		defer close()
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.items, id)
		_, err := p.store.Remove(ctx, id)
		if err != nil {
			logger.Errorf("cannot remove rendezvous %q: %v", id, err)
		}
		removed = true
	}
	if expiredErr != nil {
		if removed {
			return nil, nil, errgo.Newf("rendezvous expired after %v", p.expiryDuration)
		}
		return nil, nil, errgo.Notef(err, "rendezvous wait timed out")
	}
	// TODO what do we actually want RequestCompleted to signify?
	p.metrics.RequestCompleted(item.created)
	return item.data0, item.data1, nil
}

// localDone is the internal version of Place.Done.
// It only works if the given id is stored locally.
func (p *Place) localDone(id string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	item := p.items[id]

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

func (p *Place) isLocal(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.items[id] != nil
}

func (p *Place) newHandler(params httprequest.Params) (*handler, context.Context, error) {
	return p.handler, params.Context, nil
}

var reqServer = httprequest.Server{
	ErrorMapper: func(ctx context.Context, err error) (httpStatus int, errorBody interface{}) {
		return http.StatusInternalServerError, &httprequest.RemoteError{
			Message: err.Error(),
		}
	},
}

// NewRendezvous creates a new rendezvous holding
// the given data. The rendezvous id is returned.
func (p *Place) NewRendezvous(ctx context.Context, id string, data []byte) error {
	p.mu.Lock()
	p.items[id] = &item{
		created: Clock.Now(),
		c:       make(chan struct{}),
		data0:   data,
	}
	p.mu.Unlock()
	if err := p.store.Put(ctx, id, p.localAddr); err != nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.items, id)
		return errgo.Notef(err, "cannot create entry for rendezvous")
	}
	return nil
}

// Wait waits for the rendezvous with the given id
// and returns the data provided to NewRendezvous
// and the data provided to Done.
func (p *Place) Wait(ctx context.Context, id string) (data0, data1 []byte, err error) {
	logger.Infof("Wait %q", id)
	if p.isLocal(id) {
		return p.localWait(ctx, id)
	}
	logger.Infof("not local wait")
	client, err := p.clientForId(ctx, id)
	if err != nil {
		return nil, nil, errgo.Mask(err)
	}
	resp, err := client.Wait(ctx, &waitRequest{
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
func (p *Place) Done(ctx context.Context, id string, data []byte) error {
	if p.isLocal(id) {
		return p.localDone(id, data)
	}
	client, err := p.clientForId(ctx, id)
	if err != nil {
		return errgo.Mask(err)
	}
	if err := client.Done(ctx, &doneRequest{
		Id: id,
		Body: doneData{
			Data1: data,
		},
	}); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

func (p *Place) clientForId(ctx context.Context, id string) (*client, error) {
	addr, err := p.store.Get(ctx, id)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &client{
		Client: httprequest.Client{
			BaseURL: "http://" + addr,
		},
	}, nil
}

// noMetrics implements Metrics by doing nothing.
type noMetrics struct{}

func (noMetrics) RequestCompleted(startTime time.Time) {}

func (noMetrics) RequestsExpired(count int) {}
