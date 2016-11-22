// Copyright 2014-2016 Canonical Ltd.

package store

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/juju/idmclient/params"
	"github.com/juju/loggo"
	"github.com/juju/utils/cache"
	"github.com/pborman/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/mgostorage"
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

	// AdminAgentPublicKey contains the public key of the admin agent.
	AdminAgentPublicKey *bakery.PublicKey
}

type LimitPool interface {
	Close()
	Get(time.Duration) (limitpool.Item, error)
	GetNoLimit() limitpool.Item
	Stats() limitpool.Stats
	Put(limitpool.Item)
}

func NewMonitoredPool(gauge prometheus.Gauge, limit int, new func() limitpool.Item) *monitoredPool {
	monitoredNew := func() limitpool.Item {
		gauge.Inc()
		return new()
	}
	pool := limitpool.NewPool(limit, monitoredNew)
	return &monitoredPool{
		Pool:    pool,
		m_items: gauge,
	}
}

type monitoredPool struct {
	*limitpool.Pool
	m_items prometheus.Gauge
}

func (p *monitoredPool) Get(t time.Duration) (limitpool.Item, error) {
	i, err := p.Pool.Get(t)
	if err == nil {
		p.m_items.Dec()
	}
	return i, err
}

func (p *monitoredPool) GetNoLimit() limitpool.Item {
	i := p.Pool.GetNoLimit()
	p.m_items.Dec()
	return i
}

func (p *monitoredPool) Put(i limitpool.Item) {
	p.Pool.Put(i)
	p.m_items.Inc()
}

// Pool provides a pool of *Store objects.
type Pool struct {
	sessionPool LimitPool
	storePool   mempool.Pool

	// meetingServer holds the server used to create
	// InteractionRequired rendezvous.
	meetingServer *meeting.Server

	params         StoreParams
	db             *mgo.Database
	service        *bakery.Service
	rootKeys       *mgostorage.RootKeys
	launchpadCache *cache.Cache
}

// NewPool creates a new Pool. The pool will be sized at sp.MaxMgoSessions.
func NewPool(db *mgo.Database, sp StoreParams) (*Pool, error) {
	p := &Pool{
		db:             db,
		params:         sp,
		launchpadCache: cache.New(10 * time.Minute),
	}
	if sp.PrivateAddr == "" {
		return nil, errgo.New("no private address configured")
	}

	m_items := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "blues_identity",
		Subsystem: "store",
		Name:      "mgo_session_pool_size",
		Help:      "Size of the mongo session pool.",
	})
	prometheus.MustRegisterOrGet(m_items)

	p.sessionPool = NewMonitoredPool(m_items, sp.MaxMgoSessions, p.newSession)
	p.storePool.New = func() interface{} {
		return p.newStore()
	}
	var err error
	p.meetingServer, err = meeting.NewServer(p.newMeetingStore, newMeetingMetrics(), p.params.PrivateAddr)
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
	locator := bakery.NewThirdPartyLocatorStore()
	locator.AddInfo(p.params.Location, bakery.ThirdPartyInfo{
		PublicKey: p.params.Key.Public,
		Version:   bakery.LatestVersion,
	})
	p.service, err = bakery.NewService(bakery.NewServiceParams{
		Location: p.params.Location,
		Key:      p.params.Key,
		Locator:  locator,
	})
	if err != nil {
		return nil, errgo.Notef(err, "cannot create bakery service")
	}
	p.rootKeys = mgostorage.NewRootKeys(1000) // TODO(mhilton) make this configurable?
	s := p.GetNoLimit()
	defer p.Put(s)
	if err := s.ensureIndexes(); err != nil {
		return nil, errgo.Notef(err, "cannot ensure indexes")
	}
	if err := p.rootKeys.EnsureIndex(s.DB.Macaroons()); err != nil {
		return nil, errgo.Notef(err, "cannot ensure indexes")
	}

	cm := NewCollectionMonitor(map[string]Counter{
		"identities": db.C("identities"),
		"macaroons":  db.C("macaroons"),
		"meeting":    db.C("meeting")})
	_, err = prometheus.RegisterOrGet(cm)
	if err != nil {
		return nil, errgo.Notef(err, "could not register collection monitor")
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

	// pool holds the pool which created this Store.
	pool *Pool

	// prometheus summary monitor.
	m_getlpgroups prometheus.Summary
}

// newStore returns a new Store instance. When it's
// returned, it isn't associated with any mongo session.
func (p *Pool) newStore() *Store {
	s := &Store{
		pool: p,
	}
	s.m_getlpgroups = prometheus.NewSummary(prometheus.SummaryOpts{
		Namespace: "blues_identity",
		Subsystem: "launchpad",
		Name:      "get_launchpad_groups",
		Help:      "The duration of launchpad login, /people, and super_teams_collection_link requests.",
	})
	return s
}

type meetingMetrics struct {
	meetingCompleted prometheus.Summary
	meetingsExpired  prometheus.Counter
}

func newMeetingMetrics() *meetingMetrics {
	meetingCompleted := prometheus.NewSummary(prometheus.SummaryOpts{
		Namespace: "blues_identity",
		Subsystem: "rendevous",
		Name:      "meetings_completed_times",
		Help:      "The time between rendevous creation and its completion.",
	})
	prometheus.MustRegisterOrGet(meetingCompleted)
	meetingsExpired := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "blues_identity",
		Subsystem: "rendevous",
		Name:      "meetings_expired_count",
		Help:      "Count of rendevous which were never completed.",
	})
	prometheus.MustRegisterOrGet(meetingsExpired)
	return &meetingMetrics{
		meetingCompleted: meetingCompleted,
		meetingsExpired:  meetingsExpired,
	}
}

func (m *meetingMetrics) RequestCompleted(startTime time.Time) {
	m.meetingCompleted.Observe(float64(time.Since(startTime)) / float64(time.Microsecond))
}

func (m *meetingMetrics) RequestsExpired(count int) {
	m.meetingsExpired.Add(float64(count))
}

// setSession sets the mongo session associated with the Store.
// After this has been called, the store becomes usable
// (assuming the session is valid).
func (s *Store) setSession(session *mgo.Session) {
	s.DB.Database = s.pool.db.With(session)
	s.Place = s.pool.meetingServer.Place(mgomeeting.NewStore(s.DB.Meeting()))
	s.Service = s.pool.service.WithStore(s.pool.rootKeys.NewStorage(
		s.DB.Macaroons(),
		mgostorage.Policy{
			ExpiryDuration: 365 * 24 * time.Hour,
		},
	))
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

// UpsertIdentity creates, or updates, the identity described in the
// given document. The document with the provided username and external
// ID, or username and owner will be upserted. The email, gravatar ID and
// fullname will always be set to the values in the given document.
// Groups, SSH keys, public keys and extra info will only be set if they
// have non-nil values. Any field value pairs specified in onInsert will
// be added to the identity only if a new identity document is created.
func (s *Store) UpsertIdentity(doc *mongodoc.Identity, onInsert bson.D) error {
	doc.UUID = uuid.NewSHA1(IdentityNamespace, []byte(doc.Username)).String()
	doc.Groups = uniqueStrings(doc.Groups)
	if doc.ExternalID != "" && doc.Owner != "" {
		return errgo.New("both external_id and owner specified")
	}
	if doc.ExternalID == "" && doc.Owner == "" {
		return errgo.New("no external_id or owner specified")
	}
	query := make(bson.D, 3)
	query[0] = bson.DocElem{"_id", doc.UUID}
	query[1] = bson.DocElem{"username", doc.Username}
	if doc.ExternalID != "" {
		query[2] = bson.DocElem{"external_id", doc.ExternalID}
	} else {
		query[2] = bson.DocElem{"owner", doc.Owner}
	}
	set := make(bson.D, 3, 7)
	set[0] = bson.DocElem{"email", doc.Email}
	set[1] = bson.DocElem{"gravatarid", doc.GravatarID}
	set[2] = bson.DocElem{"fullname", doc.FullName}
	if doc.Groups != nil {
		set = append(set, bson.DocElem{"groups", doc.Groups})
	}
	if doc.SSHKeys != nil {
		set = append(set, bson.DocElem{"ssh_keys", doc.SSHKeys})
	}
	if doc.PublicKeys != nil {
		set = append(set, bson.DocElem{"public_keys", doc.PublicKeys})
	}
	if doc.ExtraInfo != nil {
		set = append(set, bson.DocElem{"extrainfo", doc.ExtraInfo})
	}
	update := make(bson.D, 1, 2)
	update[0] = bson.DocElem{"$set", set}
	if len(onInsert) > 0 {
		update = append(update, bson.DocElem{"$setOnInsert", onInsert})
	}
	_, err := s.DB.Identities().Upsert(query, update)
	if mgo.IsDup(err) {
		return errgo.WithCausef(nil, params.ErrAlreadyExists, "cannot add user: duplicate username or external_id")
	}
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// SetGroups sets the groups of a user. If the user is not found then an
// error is returned with the cause params.ErrNotFound.
func (s *Store) SetGroups(username params.Username, groups []string) error {
	err := s.UpdateIdentity(username, bson.D{{"$set", bson.D{{"groups", uniqueStrings(groups)}}}})
	if err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

// AddGroups adds the given groups to the given user. If the user is not
// found then an error is returned with the cause params.ErrNotFound.
func (s *Store) AddGroups(username params.Username, groups []string) error {
	err := s.UpdateIdentity(params.Username(username), bson.D{{
		"$addToSet", bson.D{{"groups", bson.D{{"$each", groups}}}},
	}})
	if err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

// RemoveGroups adds the given groups to the given user. If the user is not
// found then an error is returned with the cause params.ErrNotFound.
func (s *Store) RemoveGroups(username params.Username, groups []string) error {
	err := s.UpdateIdentity(username, bson.D{{"$pullAll", bson.D{{"groups", groups}}}})
	if err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

// SetPublicKeys sets the public keys of a user.
// If the user is not found then an error is returned with the cause params.ErrNotFound.
func (s *Store) SetPublicKeys(username string, publickeys []mongodoc.PublicKey) error {
	err := s.UpdateIdentity(params.Username(username), bson.D{{"$set", bson.D{{"public_keys", publickeys}}}})
	if err != nil {
		return errgo.Mask(err, errgo.Is(params.ErrNotFound))
	}
	return nil
}

// GetLaunchpadGroups gets the groups from Launchpad if the user is a launchpad user
// otherwise an empty array.
func (s *Store) GetLaunchpadGroups(externalId string) ([]string, error) {
	if !strings.HasPrefix(externalId, "https://login.ubuntu.com/+id/") {
		return nil, nil
	}
	groups, err := s.pool.launchpadCache.Get(externalId, func() (interface{}, error) {
		return s.getLaunchpadGroups(externalId)
	})
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return groups.([]string), nil
}

// getLaunchpadGroups tries to fetch the list of teams the user
// belongs to in launchpad. Only public teams are supported.
func (s *Store) getLaunchpadGroups(externalId string) ([]string, error) {
	t := time.Now()
	root, err := lpad.Login(s.pool.params.Launchpad, &lpad.OAuth{Consumer: "blues", Anonymous: true})
	if err != nil {
		return nil, errgo.Notef(err, "cannot connect to launchpad")
	}
	user, err := getLaunchpadPersonByOpenID(root, externalId)
	if err != nil {
		return nil, errgo.Notef(err, "cannot find user %s", externalId)
	}
	teams, err := user.Link("super_teams_collection_link").Get(nil)
	if err != nil {
		return nil, errgo.Notef(err, "cannot get team list for launchpad user %q", user.Name())
	}
	groups := make([]string, 0, teams.TotalSize())
	teams.For(func(team *lpad.Value) error {
		groups = append(groups, team.StringField("name"))
		return nil
	})
	s.m_getlpgroups.Observe(float64(time.Since(t)) / float64(time.Microsecond))
	return groups, nil
}

func getLaunchpadPersonByOpenID(root *lpad.Root, externalId string) (*lpad.Person, error) {
	v, err := root.Location("/people").Get(lpad.Params{"ws.op": " getByOpenIDIdentifier", "identifier": externalId})
	if err != nil {
		return nil, errgo.Notef(err, "cannot find user %s", externalId)
	}
	return &lpad.Person{v}, nil
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

type collectionMonitorEntry struct {
	collection Counter
	m          prometheus.Gauge
}

type Counter interface {
	Count() (int, error)
}

type collectionMonitor []*collectionMonitorEntry

func NewCollectionMonitor(collections map[string]Counter) collectionMonitor {
	c := collectionMonitor(make([]*collectionMonitorEntry, len(collections)))
	var i int
	for collName, collCounter := range collections {
		c[i] = &collectionMonitorEntry{
			collection: collCounter,
			m: prometheus.NewGauge(prometheus.GaugeOpts{
				Namespace: "blues_identity_collection",
				Subsystem: collName,
				Name:      "count",
				Help:      "collection size"}),
		}
		i++
	}
	return c
}

// Describe implements the prometheus.Collector interface.
func (cm collectionMonitor) Describe(c chan<- *prometheus.Desc) {
	for _, entry := range cm {
		c <- entry.m.Desc()
	}
}

// Collect implements the prometheus.Collector interface.
func (cm collectionMonitor) Collect(c chan<- prometheus.Metric) {
	for _, entry := range cm {
		cnt, err := entry.collection.Count()
		if err != nil {
			entry.m.Set(math.NaN())
			logger.Debugf("collectionMonitor Collect could not get collection count for %s: %s", entry.m.Desc(), err)
		} else {
			entry.m.Set(float64(cnt))
		}
		c <- entry.m
	}
}
