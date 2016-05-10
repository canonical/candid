// Copyright 2014 Canonical Ltd.

package store

import (
	"sort"
	"strings"
	"time"

	"github.com/juju/idmclient/params"
	"github.com/juju/loggo"
	"github.com/pborman/uuid"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v1/bakery"
	"gopkg.in/macaroon-bakery.v1/bakery/mgostorage"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"launchpad.net/lpad"

	"github.com/CanonicalLtd/blues-identity/internal/limitpool"
	"github.com/CanonicalLtd/blues-identity/internal/mempool"
	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/meeting"
	"github.com/CanonicalLtd/blues-identity/meeting/mgomeeting"
)

var logger = loggo.GetLogger("identity.internal.store")
var IdentityNamespace = uuid.Parse("685c2eaa-9721-11e4-b717-a7bf1a250a86")

// StoreParams contains configuration parameters for a store.
type StoreParams struct {
	// AuthUsername holds the username for admin login.
	AuthUsername string

	// AuthPassword holds the password for admin login.
	AuthPassword string

	// Key holds the keypair to use with the bakery service.
	Key *bakery.KeyPair

	// Location holds a URL representing the externally accessible
	// base URL of the service, without a trailing slash.
	Location string

	// Launchpad holds the address of the launchpad server to use to
	// get group information.
	Launchpad lpad.APIBase

	// MaxMgoSession holds the maximum number of concurrent mgo
	// sessions.
	MaxMgoSessions int

	// RequestTimeout holds the time to wait for a request to be able
	// to start.
	RequestTimeout time.Duration

	// PrivateAddr should hold a dialable address that will be used
	// for communication between identity servers. Note that this
	// should not contain a port.
	PrivateAddr string
}

// Pool provides a pool of *Store objects.
type Pool struct {
	sessionPool *limitpool.Pool
	storePool   mempool.Pool

	// meetingServer holds the server used to create
	// InteractionRequired rendezvous.
	meetingServer *meeting.Server

	params StoreParams
	db     *mgo.Database
}

// NewPool creates a new Pool. The pool will be sized at sp.MaxMgoSessions.
func NewPool(db *mgo.Database, sp StoreParams) (*Pool, error) {
	p := &Pool{
		db:     db,
		params: sp,
	}
	if sp.PrivateAddr == "" {
		return nil, errgo.New("no private address configured")
	}
	p.sessionPool = limitpool.NewPool(sp.MaxMgoSessions, p.newSession)
	p.storePool.New = func() interface{} {
		return p.newStore()
	}
	// TODO replace localhost by actual address of server.
	var err error
	p.meetingServer, err = meeting.NewServer(p.newMeetingStore, p.params.PrivateAddr)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	if p.params.Key == nil {
		var err error
		p.params.Key, err = bakery.GenerateKey()
		if err != nil {
			return nil, errgo.Notef(err, "cannot generate key")
		}
	}
	s := p.GetNoLimit()
	defer p.Put(s)
	if err := s.ensureIndexes(); err != nil {
		return nil, errgo.Notef(err, "cannot ensure indexes")
	}
	return p, nil
}

// newMeetingStore returns a new meeting.Store.
func (p *Pool) newMeetingStore() meeting.Store {
	session := p.getSessionNoLimit()
	db := StoreDatabase{p.db.With(session)}
	return &poolMeetingStore{
		pool:    p,
		session: session,
		Store:   mgomeeting.NewStore(db.Meeting()),
	}
}

func (p *Pool) newSession() limitpool.Item {
	return p.db.Session.Copy()
}

// Get retrieves a Store object from the pool if there is one available.
// If none are available it waits for the time specified as the
// RequestTimeout in the ServiceParameters for one to become available.
// If a *Store does not become available in that time it returns an error
// with a cause of params.ErrServiceUnavailable.
func (p *Pool) Get() (*Store, error) {
	session, err := p.getSession()
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(params.ErrServiceUnavailable))
	}
	// Now associate the store we've just acquired with
	// the session we've also acquired.
	store := p.storePool.Get().(*Store)
	store.setSession(session)
	return store, nil
}

// getSessionNoLimit returns a session from the session limit-pool
// without deferring to the limit.
// The session must be returned to the pool with putSession
// after use.
func (p *Pool) getSessionNoLimit() *mgo.Session {
	return p.sessionPool.GetNoLimit().(*mgo.Session)
}

// getSesson returns a session from the session limit-pool.
// The session must be returned to the pool with putSession
// after use.
func (p *Pool) getSession() (*mgo.Session, error) {
	v, err := p.sessionPool.Get(p.params.RequestTimeout)
	if err == limitpool.ErrLimitExceeded {
		return nil, errgo.WithCausef(err, params.ErrServiceUnavailable, "too many mongo sessions in use")
	}
	if err != nil {
		// This should be impossible.
		return nil, errgo.Notef(err, "cannot get Session")
	}
	return v.(*mgo.Session), nil
}

func (p *Pool) putSession(session *mgo.Session) {
	session.Refresh()
	p.sessionPool.Put(session)
}

// GetNoLimit immediately retrieves a Store from the pool. If there is no
// Store available one will be created, even if that overflows the limit.
func (p *Pool) GetNoLimit() *Store {
	store := p.storePool.Get().(*Store)
	store.setSession(p.getSessionNoLimit())
	return store
}

// Put places a Store back into the pool. Put will automatically close
// the Store if it cannot go back into the pool.
func (p *Pool) Put(s *Store) {
	p.putSession(s.DB.Session)
	p.storePool.Put(s)
}

// Stats returns information about the current pool statistics.
func (p *Pool) Stats() limitpool.Stats {
	return p.sessionPool.Stats()
}

// Close clears out the pool closing the contained stores and prevents
// any new Stores from being added.
func (p *Pool) Close() {
	// Note that the meetingServer (indirectly) uses the session
	// pool, so we need to close it down before closing the session
	// pool.
	p.meetingServer.Close()
	p.sessionPool.Close()
	p.db.Session.Close()
}

// Store represents the underlying identity data store.
type Store struct {
	// DB holds the mongodb-backed identity store.
	DB StoreDatabase

	// Service holds a *bakery.Service that can be used to make and check macaroons.
	Service *bakery.Service

	// Place holds the place where openid-callback rendezvous
	// are created.
	Place *meeting.Place

	// bakeryStore holds the bakery storage that
	// will be used by Service.
	bakeryStore bakery.Storage

	// pool holds the pool which created this Store.
	pool *Pool
}

// newStore returns a new Store instance. When it's
// returned, it isn't associated with any mongo session.
func (p *Pool) newStore() *Store {
	s := &Store{
		pool: p,
	}
	var err error
	s.Service, err = bakery.NewService(bakery.NewServiceParams{
		Location: p.params.Location,
		Store:    bakeryStore{s},
		Key:      p.params.Key,
		Locator: bakery.PublicKeyLocatorMap{
			p.params.Location + "/v1/discharger": &p.params.Key.Public,
		},
	})
	if err != nil {
		// bakery.NewService only returns an error if the key
		// cannot be created. The key will always have been
		// generated before it is called so it should not happen.
		panic(errgo.Notef(err, "cannot create bakery service"))
	}
	return s
}

// setSession sets the mongo session associated with the Store.
// After this has been called, the store becomes usable
// (assuming the session is valid).
func (s *Store) setSession(session *mgo.Session) {
	s.DB.Database = s.pool.db.With(session)
	s.Place = s.pool.meetingServer.Place(mgomeeting.NewStore(s.DB.Meeting()))
	ms, err := mgostorage.New(s.DB.Macaroons())
	if err != nil {
		// mgostorage.New no longer returns an error, so this
		// cannot happen.
		panic(errgo.Notef(err, "cannot create macaroon store"))
	}
	s.bakeryStore = ms
}

func (s *Store) ensureIndexes() error {
	indexes := []struct {
		c *mgo.Collection
		i mgo.Index
	}{{
		s.DB.Identities(),
		mgo.Index{
			Key:    []string{"username"},
			Unique: true,
		},
	}, {
		s.DB.Identities(),
		mgo.Index{
			Key:    []string{"external_id"},
			Unique: true,
			Sparse: true,
		},
	}}
	for _, idx := range indexes {
		err := idx.c.EnsureIndex(idx.i)
		if err != nil {
			return errgo.Mask(err)
		}
	}
	if err := mgomeeting.CreateCollection(s.DB.Meeting()); err != nil {
		return errgo.Mask(err)
	}

	return nil
}

// InsertIdentity adds an identity to the identities collection.
// InsertIdentity will only insert an existing entry when both the UserName and
// ExternalID match the destination record. If the Identity clashes with an existing
// Identity then an error is returned with the cause params.ErrAlreadyExists.
func (s *Store) InsertIdentity(doc *mongodoc.Identity) error {
	doc.UUID = uuid.NewSHA1(IdentityNamespace, []byte(doc.Username)).String()
	doc.Groups = uniqueStrings(doc.Groups)
	if doc.ExternalID != "" && doc.Owner != "" {
		return errgo.New("both external_id and owner specified")
	}
	if doc.ExternalID == "" && doc.Owner == "" {
		return errgo.New("no external_id or owner specified")
	}
	err := s.DB.Identities().Insert(doc)
	if mgo.IsDup(err) {
		return errgo.WithCausef(nil, params.ErrAlreadyExists, "cannot add user: duplicate username or external_id")
	}
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// UpdateGroups updates the groups of a user.
// If the user is not found then an error is returned with the cause params.ErrNotFound.
func (s *Store) UpdateGroups(doc *mongodoc.Identity) error {
	if strings.HasPrefix(doc.ExternalID, "https://login.ubuntu.com/+id/") {
		lpgroups, err := s.getLaunchpadGroups(doc.Email)
		if err == nil {
			doc.Groups = append(doc.Groups, lpgroups...)
		} else {
			logger.Warningf("failed to fetch list of groups from launchpad for %q: %s", doc.Email, err)
		}
	}
	err := s.UpdateIdentity(params.Username(doc.Username), bson.D{{"$set", bson.D{{"groups", uniqueStrings(doc.Groups)}}}})
	if err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

// getLaunchpadGroups tries to fetch the list of teams the user
// belongs to in launchpad. Only public teams are supported.
func (s *Store) getLaunchpadGroups(email string) ([]string, error) {
	root, err := lpad.Login(s.pool.params.Launchpad, &lpad.OAuth{Consumer: "blues", Anonymous: true})
	if err != nil {
		return nil, errgo.Notef(err, "cannot connect to launchpad")
	}
	people, err := root.FindPeople(email)
	if err != nil {
		return nil, errgo.Notef(err, "cannot find user %q", email)
	}
	if people.TotalSize() != 1 {
		return nil, errgo.Newf("cannot find user %q", email)
	}
	var user *lpad.Person
	people.For(func(p *lpad.Person) error {
		user = p
		return nil
	})
	teams := user.Link("super_teams_collection_link")
	teams, err = teams.Get(nil)
	if err != nil {
		return nil, errgo.Notef(err, "cannot get team list for launchpad user %q", user.Name())
	}
	groups := make([]string, 0, teams.TotalSize())
	teams.For(func(team *lpad.Value) error {
		groups = append(groups, team.StringField("name"))
		return nil
	})
	return groups, nil
}

// GetIdentity retrieves the identity with the given username. If the
// identity does not exist an error is returned with a cause of
// params.ErrNotFound.
func (s *Store) GetIdentity(username params.Username) (*mongodoc.Identity, error) {
	var id mongodoc.Identity
	if err := s.DB.Identities().Find(bson.M{"username": username}).One(&id); err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return nil, errgo.WithCausef(err, params.ErrNotFound, "user %q not found", username)
		}
		return nil, errgo.Mask(err)
	}
	return &id, nil
}

// UpdateIdentity updates the identity with the given username. If the
// identity does not exist an error is returned with a cause of
// params.ErrNotFound.
func (s *Store) UpdateIdentity(username params.Username, update bson.D) error {
	if err := s.DB.Identities().Update(bson.D{{"username", username}}, update); err != nil {
		if errgo.Cause(err) == mgo.ErrNotFound {
			return errgo.WithCausef(err, params.ErrNotFound, "user %q not found", username)
		}
		return errgo.Mask(err)
	}
	return nil
}

// Close returns the store to the pool
func (s *Store) Close() {
	s.DB.Close()
}

// StoreDatabase wraps an mgo.DB ands adds a few convenience methods.
type StoreDatabase struct {
	*mgo.Database
}

// Close closes the store database's underlying session.
func (s StoreDatabase) Close() {
	s.Session.Close()
}

// Entities returns the mongo collection where entities are stored.
func (s StoreDatabase) Identities() *mgo.Collection {
	return s.C("identities")
}

// Macaroons returns the mongo collection where macaroons are stored.
func (s StoreDatabase) Macaroons() *mgo.Collection {
	return s.C("macaroons")
}

func (s StoreDatabase) Meeting() *mgo.Collection {
	return s.C("meeting")
}

// IdentityProviders returns the mongo collection where identity providers are stored.
func (s StoreDatabase) IdentityProviders() *mgo.Collection {
	return s.C("identity_providers")
}

// allCollections holds for each collection used by the identity service a
// function returning that collection.
// TODO consider adding other collections here.
var allCollections = []func(StoreDatabase) *mgo.Collection{
	StoreDatabase.Identities,
	StoreDatabase.Meeting,
}

// Collections returns a slice of all the collections used
// by the identity service.
func (s StoreDatabase) Collections() []*mgo.Collection {
	cs := make([]*mgo.Collection, len(allCollections))
	for i, f := range allCollections {
		cs[i] = f(s)
	}
	return cs
}

// bakeryStore implements bakery.Storage by redirecting
// its storage requests to s.store.bakeryStore.
//
// We do this so that we can replace the bakeryStore
// value without needing to create a new bakery service
// for every request.
type bakeryStore struct {
	store *Store
}

func (s bakeryStore) Put(location, item string) error {
	return s.store.bakeryStore.Put(location, item)
}

func (s bakeryStore) Get(location string) (string, error) {
	return s.store.bakeryStore.Get(location)
}

func (s bakeryStore) Del(location string) error {
	return s.store.bakeryStore.Del(location)
}

// poolMeetingStore implements meeting.Store by
// wrapping the Store returned by mgomeeting
// and returning its session to the session pool
// when it is closed.
type poolMeetingStore struct {
	pool    *Pool
	session *mgo.Session
	meeting.Store
}

func (s *poolMeetingStore) Close() {
	s.pool.putSession(s.session)
}

// uniqueStrings removes all duplicates from the supplied
// string slice, updating the slice in place.
// The values will be in lexicographic order.
func uniqueStrings(ss []string) []string {
	if len(ss) < 2 {
		return ss
	}
	sort.Strings(ss)
	prev := ss[0]
	out := ss[:1]
	for _, s := range ss[1:] {
		if s == prev {
			continue
		}
		out = append(out, s)
		prev = s
	}
	return out
}
