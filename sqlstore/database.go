package sqlstore

import (
	"bytes"
	"database/sql"
	"strings"
	"text/template"

	errgo "gopkg.in/errgo.v1"

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
	return errgo.Mask(d.driver.Close())
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
	numTmpl
)

type stmtID int

const (
	stmtIdentityFromID stmtID = iota
	stmtIdentityFromProviderID
	stmtIdentityFromUsername
	stmtGroups
	stmtPublicKeys
	stmtProviderInfo
	stmtExtraInfo
	numStmt
)

type queryer interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

type stmter interface {
	Stmt(stmt *sql.Stmt) *sql.Stmt
}

// Store returns a new store.Store implementation using this database for
// persistent storage.
func (d *Database) Store() store.Store {
	return &identityStore{d}
}

type driver struct {
	stmts           [numStmt]*sql.Stmt
	tmpls           [numTmpl]*template.Template
	parameterFunc   func(int) string
	isDuplicateFunc func(error) bool
}

func (d *driver) Close() error {
	for _, s := range d.stmts {
		if err := s.Close(); err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

// Exec performs the Exec method on the given queryer by processing the
// given template with the given params to determine the query to
// execute.
func (d *driver) Exec(q queryer, tmplID tmplID, params interface{}, args ...interface{}) (sql.Result, error) {
	query, err := d.executeTemplate(tmplID, params)
	if err != nil {
		return nil, errgo.Notef(err, "cannot build query")
	}
	res, err := q.Exec(query, args...)
	return res, errgo.Mask(err, errgo.Any)
}

// Query performs the Query method on the given queryer by processing the
// given template with the given params to determine the query to
// execute.
func (d *driver) Query(q queryer, tmplID tmplID, params interface{}, args ...interface{}) (*sql.Rows, error) {
	query, err := d.executeTemplate(tmplID, params)
	if err != nil {
		return nil, errgo.Notef(err, "cannot build query")
	}
	rows, err := q.Query(query, args...)
	return rows, errgo.Mask(err, errgo.Any)
}

// QueryRow performs the QueryRow method on the given queryer by
// processing the given template with the given params to determine the
// query to execute.
func (d *driver) QueryRow(q queryer, tmplID tmplID, params interface{}, args ...interface{}) (*sql.Row, error) {
	query, err := d.executeTemplate(tmplID, params)
	if err != nil {
		return nil, errgo.Notef(err, "cannot build query")
	}
	return q.QueryRow(query, args...), nil
}

// Prepare performs the Prepare method on the given db by processing the
// given template with the given params to determine the statement to
// prepare.
func (d *driver) Prepare(db *sql.DB, stmtID stmtID, tmplID tmplID, params interface{}) error {
	stmt, err := d.executeTemplate(tmplID, params)
	if err != nil {
		return errgo.Notef(err, "cannot build query")
	}
	d.stmts[stmtID], err = db.Prepare(stmt)
	return errgo.Mask(err)
}

func (d *driver) Stmt(s stmter, stmtID stmtID) *sql.Stmt {
	return s.Stmt(d.stmts[stmtID])
}

func (d *driver) parseTemplate(tmplID tmplID, tmpl string) error {
	var err error
	d.tmpls[tmplID], err = template.New("").Funcs(template.FuncMap{
		"join":      strings.Join,
		"parameter": d.parameterFunc,
		"values":    d.values,
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

func (d *driver) values(start, rows, columns int) string {
	buf := new(bytes.Buffer)
	n := start
	for i := 0; i < rows; i++ {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteByte('(')
		for j := 0; j < columns; j++ {
			if j > 0 {
				buf.WriteString(", ")
			}
			buf.WriteString(d.parameterFunc(n))
			n++
		}
		buf.WriteByte(')')
	}
	return buf.String()
}

var comparisons = map[store.Comparison]string{
	store.Equal:              "=",
	store.NotEqual:           "<>",
	store.GreaterThan:        ">",
	store.LessThan:           "<",
	store.GreaterThanOrEqual: ">=",
	store.LessThanOrEqual:    "<=",
}
