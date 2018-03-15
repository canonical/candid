package sqlstore

import (
	"bytes"
	"database/sql"
	"strings"
	"text/template"

	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/meeting"
	"github.com/CanonicalLtd/blues-identity/store"
)

// A Database provides a wrapper around an SQL database that can be used
// as the persistent storage for the various types of store required by
// the identity service.
type Database struct {
	db     *sql.DB
	driver *driver
}

// NewDatabase creates a new Database using the given driverName and
// *sql.DB. The driverName must match the value used to open the
// database.
func NewDatabase(driverName string, db *sql.DB) (*Database, error) {
	if driverName != "postgres" {
		return nil, errgo.Newf("unsupported database driver %q", driverName)
	}
	driver, err := newPostgresDriver(db)
	if err != nil {
		return nil, errgo.Notef(err, "cannot initialise database")
	}
	return &Database{
		db:     db,
		driver: driver,
	}, nil
}

func (d *Database) Close() error {
	return nil
}

// Store returns a new store.Store implementation using this database for
// persistent storage.
func (d *Database) Store() store.Store {
	return &identityStore{d}
}

// ProviderDataStore returns a new store.ProviderDataStore implementation
// using this database for persistent storage.
func (d *Database) ProviderDataStore() store.ProviderDataStore {
	return &providerDataStore{d}
}

// MeetingStore returns a new meeting.Stor implementation using this
// database for persistent storage.
func (d *Database) MeetingStore() meeting.Store {
	return &meetingStore{d}
}

// withTx runs f in a new transaction. any error returned by f will not
// have it's cause masked.
func (d *Database) withTx(f func(*sql.Tx) error) error {
	tx, err := d.db.Begin()
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
	tmplInsertProviderData
	tmplGetMeeting
	tmplPutMeeting
	tmplFindMeetings
	tmplRemoveMeetings
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
	// the next argument to be used in the query. Arg should remmebre
	// the value and return a valid placeholder to access that
	// argument when executing the query.
	Arg(interface{}) string

	// args returns the slice of arguments that should be used when
	// executing the query.
	args() []interface{}
}

type driver struct {
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
