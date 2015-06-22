// Copyright 2014 Canonical Ltd.

package v1

import (
	"net/http"

	"github.com/juju/httprequest"
	"github.com/juju/loggo"
	"github.com/julienschmidt/httprouter"
	"github.com/kushaldas/openid.go/src/openid"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery/checkers"

	"github.com/CanonicalLtd/blues-identity/internal/identity"
	"github.com/CanonicalLtd/blues-identity/params"
)

var logger = loggo.GetLogger("identity.internal.v1")

const (
	opAdmin         checkers.OperationChecker = "admin"
	opCreateAgent   checkers.OperationChecker = "create-agent"
	opCreateUser    checkers.OperationChecker = "create-user"
	opGetUser       checkers.OperationChecker = "get-user"
	opGetUserGroups checkers.OperationChecker = "get-user-groups"
)

// Handler handles the /v1 api requests. Handler implements http.Handler
type Handler struct {
	storePool      *identity.Pool
	handlerPool    pool
	r              *httprouter.Router
	location       string
	nonceStore     *openid.SimpleNonceStore
	discoveryCache *openid.SimpleDiscoveryCache
}

// NewAPIHandler returns a new Handler as an http Handler.
// It is defined for the convenience of callers that require a
// identity.NewAPIHandlerFunc.
func NewAPIHandler(p *identity.Pool, sp identity.ServerParams) http.Handler {
	return New(p, sp)
}

// New returns a new instance of the v1 API handler.
func New(p *identity.Pool, sp identity.ServerParams) *Handler {
	h := &Handler{
		storePool: p,
		r:         httprouter.New(),
		location:  sp.Location,
		nonceStore: &openid.SimpleNonceStore{
			Store: make(map[string][]*openid.Nonce),
		},
		discoveryCache: &openid.SimpleDiscoveryCache{},
	}
	h.handlerPool = newPool(h.newHandler)
	// Redirection does not work because the router does not know
	// about the /v1 prefix. Disable the automatic redirection features.
	h.r.RedirectTrailingSlash = false
	h.r.RedirectFixedPath = false
	h.r.NotFound = notFound
	h.r.MethodNotAllowed = methodNotAllowed
	for _, hnd := range errorMapper.Handlers(h.handler) {
		h.r.Handle(hnd.Method, hnd.Path, hnd.Handle)
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.r.ServeHTTP(w, req)
}

// handler creates a per-request handler. This method conforms to the
// specification for
// https://godoc.org/github.com/juju/httprequest#ErrorMapper.Handlers and
// so can be used to automatically derive the list of endpoints to add to
// the router.
func (h *Handler) handler(httprequest.Params) (*handler, error) {
	store, err := h.storePool.Get()
	if err != nil {
		return nil, errgo.NoteMask(err, "cannot get store", errgo.Any)
	}
	handler := h.handlerPool.Get().(*handler)
	handler.store = store
	handler.place = &place{store.Place}
	return handler, nil
}

func (h *Handler) newHandler() interface{} {
	return &handler{
		h:              h,
		storePool:      h.storePool,
		handlerPool:    h.handlerPool,
		location:       h.location,
		nonceStore:     h.nonceStore,
		discoveryCache: h.discoveryCache,
	}
}

type handler struct {
	storePool      *identity.Pool
	handlerPool    pool
	store          *identity.Store
	h              *Handler
	location       string
	place          *place
	nonceStore     *openid.SimpleNonceStore
	discoveryCache *openid.SimpleDiscoveryCache
}

func (h *handler) checkAdmin(r *http.Request) error {
	return h.store.CheckACL(opAdmin, r, []string{identity.AdminGroup})
}

// Close implements io.Closer. httprequest will automatically call this
// once a request is complete.
func (h *handler) Close() error {
	h.storePool.Put(h.store)
	h.store = nil
	h.place = nil
	h.handlerPool.Put(h)
	return nil
}

type pool interface {
	Get() interface{}
	Put(interface{})
}

var errNotImplemented = errgo.Newf("method not implemented")

// requestURL calculates the originally requested URL for the
// provided http.Request.
func (h *handler) requestURL(r *http.Request) string {
	return h.location + r.RequestURI
}

//notFound is the handler that is called when a handler cannot be found
//for the requested endpoint.
func notFound(w http.ResponseWriter, req *http.Request) {
	writeError(w, errgo.WithCausef(nil, params.ErrNotFound, "not found: %s", req.URL.Path))
}

//methodNotAllowed is the handler that is called when a handler cannot
//be found for the requested endpoint with the request method, but
//there is a handler avaiable using a different method.
func methodNotAllowed(w http.ResponseWriter, req *http.Request) {
	writeError(w, errgo.WithCausef(nil, params.ErrMethodNotAllowed, "%s not allowed for %s", req.Method, req.URL.Path))
}
