package sqlstore

import (
	"bytes"
	"database/sql"
	"strings"
	"text/template"
	"time"

	"github.com/juju/aclstore/v2"
	"github.com/juju/simplekv/sqlsimplekv"
	"github.com/juju/utils/debugstatus"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/postgresrootkeystore"

	"github.com/CanonicalLtd/candid/meeting"
	"github.com/CanonicalLtd/candid/store"
)

// backend provides a wrapper around an SQL database that can be used
// as the persistent storage for the various types of store required by
// the identity service.
type backend struct {
	db       *sql.DB
	driver   *driver
	rootKeys *postgresrootkeystore.RootKeys
	aclStore aclstore.ACLStore
}

// NewBackend creates a new store.Backend implementation using the
// given driverName and *sql.DB. The driverName must match the value
// used to open the database.
//
// Closing the returned Backend will also close db.
func NewBackend(driverName string, db *sql.DB) (store.Backend, error) {
	if driverName != "postgres" {
		return nil, errgo.Newf("unsupported database driver %q", driverName)
	}
	driver, err := newPostgresDriver(db)
	if err != nil {
		return nil, errgo.Notef(err, "cannot initialise database")
	}
	rootkeys := postgresrootkeystore.NewRootKeys(db, "rootkeys", 1000)
	defer rootkeys.Close()
	aclStore, err := sqlsimplekv.NewStore(driverName, db, "acls")
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &backend{
		db:       db,
		driver:   driver,
		rootKeys: postgresrootkeystore.NewRootKeys(db, "rootkeys", 1000),
		aclStore: aclstore.NewACLStore(aclStore),
	}, nil
}

func (b *backend) Close() {
	b.rootKeys.Close()
	b.db.Close()
}

// Store returns a new store.Store implementation using this database for
// persistent storage.
func (b *backend) Store() store.Store {
	return &identityStore{b}
}

func (b *backend) BakeryRootKeyStore() bakery.RootKeyStore {
	return b.rootKeys.NewStore(postgresrootkeystore.Policy{
		ExpiryDuration: 365 * 24 * time.Hour,
	})
}

// ProviderDataStore returns a new store.ProviderDataStore implementation
// using this database for persistent storage.
func (b *backend) ProviderDataStore() store.ProviderDataStore {
	return &providerDataStore{b}
}

// MeetingStore returns a new meeting.Stor implementation using this
// database for persistent storage.
func (b *backend) MeetingStore() meeting.Store {
	return &meetingStore{b}
}

func (b *backend) ACLStore() aclstore.ACLStore {
	return b.aclStore
}

// DebugStatusCheckerFuncs implements store.Backend.DebugStatusCheckerFuncs.
func (b *backend) DebugStatusCheckerFuncs() []debugstatus.CheckerFunc {
	return nil
}

// withTx runs f in a new transaction. any error returned by f will not
// have it's cause masked.
func (b *backend) withTx(f func(*sql.Tx) error) error {
	tx, err := b.db.Begin()
	if err != nil {
		return errgo.Mask(err)
	}
	if err := f(tx); err != nil {
		if err := tx.Rollback(); err != nil {
			logger.Errorf("failed to rollback transaction: %s", err)
		}
		return errgo.Mask(err, errgo.Any)
	}
	return errgo.Mask(tx.Commit())
}

type tmplID int

const (
	tmplIdentityFrom tmplID = iota
	tmplSelectIdentitySet
	tmplFindIdentities
	tmplUpdateIdentity
	tmplIdentityID
	tmplUpsertIdentity
	tmplClearIdentitySet
	tmplPushIdentitySet
	tmplPullIdentitySet
	tmplGetProviderData
	tmplGetProviderDataForUpdate
	tmplInsertProviderData
	tmplGetMeeting
	tmplPutMeeting
	tmplFindMeetings
	tmplRemoveMeetings
	tmplIdentityCounts
	numTmpl
)

type queryer interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

// argBuilder is an interface that can be embedded in template parameters
// to record the arguments needed to be supplied with SQL queries.
type argBuilder interface {
	// Arg is a method that is called in templates with the value of
	// the next argument to be used in the query. Arg should remember
	// the value and return a valid placeholder to access that
	// argument when executing the query.
	Arg(interface{}) string

	// args returns the slice of arguments that should be used when
	// executing the query.
	args() []interface{}
}

type driver struct {
	name            string
	tmpls           [numTmpl]*template.Template
	argBuilderFunc  func() argBuilder
	isDuplicateFunc func(error) bool
}

// exec performs the Exec method on the given queryer by processing the
// given template with the given params to determine the query to
// execute.
func (d *driver) exec(q queryer, tmplID tmplID, params argBuilder) (sql.Result, error) {
	query, err := d.executeTemplate(tmplID, params)
	if err != nil {
		return nil, errgo.Notef(err, "cannot build query")
	}
	res, err := q.Exec(query, params.args()...)
	return res, errgo.Mask(err, errgo.Any)
}

// query performs the Query method on the given queryer by processing the
// given template with the given params to determine the query to
// execute.
func (d *driver) query(q queryer, tmplID tmplID, params argBuilder) (*sql.Rows, error) {
	query, err := d.executeTemplate(tmplID, params)
	if err != nil {
		return nil, errgo.Notef(err, "cannot build query")
	}
	rows, err := q.Query(query, params.args()...)
	return rows, errgo.Mask(err, errgo.Any)
}

// queryRow performs the QueryRow method on the given queryer by
// processing the given template with the given params to determine the
// query to execute.
func (d *driver) queryRow(q queryer, tmplID tmplID, params argBuilder) (*sql.Row, error) {
	query, err := d.executeTemplate(tmplID, params)
	if err != nil {
		return nil, errgo.Notef(err, "cannot build query")
	}
	return q.QueryRow(query, params.args()...), nil
}

func (d *driver) parseTemplate(tmplID tmplID, tmpl string) error {
	var err error
	d.tmpls[tmplID], err = template.New("").Funcs(template.FuncMap{
		"join": strings.Join,
	}).Parse(tmpl)
	return errgo.Mask(err)
}

func (d *driver) executeTemplate(tmplID tmplID, params interface{}) (string, error) {
	buf := new(bytes.Buffer)
	if err := d.tmpls[tmplID].Execute(buf, params); err != nil {
		return "", errgo.Mask(err)
	}
	return buf.String(), nil
}

var comparisons = map[store.Comparison]string{
	store.Equal:              "=",
	store.NotEqual:           "<>",
	store.GreaterThan:        ">",
	store.LessThan:           "<",
	store.GreaterThanOrEqual: ">=",
	store.LessThanOrEqual:    "<=",
}
