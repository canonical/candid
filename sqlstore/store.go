package sqlstore

import (
	"database/sql"
	sqldriver "database/sql/driver"
	"fmt"
	"strconv"
	"time"

	"github.com/juju/loggo"
	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/blues-identity/store"
)

var logger = loggo.GetLogger("blues-identity.sqlstore")

var identityColumns = [store.NumFields]string{
	store.ProviderID:    "providerid",
	store.Username:      "username",
	store.Name:          "name",
	store.Email:         "email",
	store.LastLogin:     "lastlogin",
	store.LastDischarge: "lastdischarge",
}

type identityStore struct {
	*Database
}

// Context implements store.Context, it returns the given context unmodified.
func (*identityStore) Context(ctx context.Context) (context.Context, func()) {
	return ctx, func() {}
}

// Identity implements store.Identity.
func (s *identityStore) Identity(ctx context.Context, identity *store.Identity) error {
	return errgo.Mask(s.withTx(func(tx *sql.Tx) error {
		return s.identity(tx, identity)
	}), errgo.Is(store.ErrNotFound))
}

func (s *identityStore) identity(tx *sql.Tx, identity *store.Identity) error {
	var stmtID stmtID
	var arg interface{}
	switch {
	case identity.ID != "":
		stmtID = stmtIdentityFromID
		arg = identity.ID
	case identity.ProviderID != "":
		stmtID = stmtIdentityFromProviderID
		arg = identity.ProviderID
	case identity.Username != "":
		stmtID = stmtIdentityFromUsername
		arg = identity.Username
	default:
		return store.NotFoundError("", "", "")
	}
	stmt := s.driver.Stmt(tx, stmtID)
	err := scanIdentity(stmt.QueryRow(arg), identity)
	stmt.Close()
	if errgo.Cause(err) == sql.ErrNoRows {
		return store.NotFoundError(identity.ID, identity.ProviderID, identity.Username)
	}
	if err != nil {
		return errgo.Notef(err, "cannot get identity")
	}
	if err := s.completeIdentity(tx, identity); err != nil {
		return errgo.Notef(err, "cannot get identity")
	}
	return nil
}

// FindIdentities implements store.FindIdentities.
func (s *identityStore) FindIdentities(ctx context.Context, ref *store.Identity, filter store.Filter, sort []store.Sort, skip, limit int) ([]store.Identity, error) {
	var identities []store.Identity
	err := s.withTx(func(tx *sql.Tx) error {
		var err error
		identities, err = s.findIdentities(tx, ref, filter, sort, skip, limit)
		return err
	})
	if err != nil {
		return nil, errgo.Notef(err, "cannot find identities")
	}
	return identities, nil
}

type findParams struct {
	Where []string
	Sort  []string
	Limit int
	Skip  int
}

func (s *identityStore) findIdentities(tx *sql.Tx, ref *store.Identity, filter store.Filter, sort []store.Sort, skip, limit int) ([]store.Identity, error) {
	var where []string
	var args []interface{}
	n := 1
	for f, op := range filter {
		col := identityColumns[f]
		cond := comparisons[op]
		if col == "" || cond == "" {
			continue
		}

		where = append(where, fmt.Sprintf("%s%s%s", col, cond, s.driver.parameterFunc(n)))
		args = append(args, fieldValue(store.Field(f), ref))
		n++
	}

	sorts := make([]string, 0, len(sort))
	for _, s := range sort {
		col := identityColumns[s.Field]
		if col == "" {
			continue
		}
		if s.Descending {
			col += " DESC"
		}
		sorts = append(sorts, col)
	}

	params := findParams{
		Where: where,
		Sort:  sorts,
		Limit: limit,
		Skip:  skip,
	}
	rows, err := s.driver.Query(tx, tmplFindIdentities, params, args...)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer rows.Close()
	var identities []store.Identity
	for rows.Next() {
		var identity store.Identity
		if err := scanIdentity(rows, &identity); err != nil {
			return nil, errgo.Mask(err)
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, errgo.Mask(err)
	}
	for i := range identities {
		if err := s.completeIdentity(tx, &identities[i]); err != nil {
			return nil, errgo.Mask(err)
		}
	}
	return identities, nil
}

func fieldValue(f store.Field, id *store.Identity) interface{} {
	switch f {
	case store.ProviderID:
		return id.ProviderID
	case store.Username:
		return id.Username
	case store.Name:
		if id.Name == "" {
			return nil
		}
		return id.Name
	case store.Email:
		if id.Email == "" {
			return nil
		}
		return id.Email
	case store.LastLogin:
		if id.LastLogin.IsZero() {
			return nil
		}
		return id.LastLogin
	case store.LastDischarge:
		if id.LastDischarge.IsZero() {
			return nil
		}
		return id.LastDischarge
	}
	return nil
}

func (s *identityStore) completeIdentity(tx *sql.Tx, identity *store.Identity) error {
	var err error
	identity.Groups, err = s.getGroups(tx, identity.ID)
	if err != nil {
		return errgo.Mask(err)
	}
	identity.PublicKeys, err = s.getPublicKeys(tx, identity.ID)
	if err != nil {
		return errgo.Mask(err)
	}
	identity.ProviderInfo, err = s.getInfoMap(tx, stmtProviderInfo, identity.ID)
	if err != nil {
		return errgo.Mask(err)
	}
	identity.ExtraInfo, err = s.getInfoMap(tx, stmtExtraInfo, identity.ID)
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

func (s *identityStore) getGroups(tx *sql.Tx, id string) ([]string, error) {
	stmt := s.driver.Stmt(tx, stmtGroups)
	defer stmt.Close()
	rows, err := stmt.Query(id)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer rows.Close()
	var groups []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, errgo.Mask(err)
		}
		groups = append(groups, g)
	}
	return groups, errgo.Mask(rows.Err())
}

func (s *identityStore) getPublicKeys(tx *sql.Tx, id string) ([]bakery.PublicKey, error) {
	stmt := s.driver.Stmt(tx, stmtPublicKeys)
	defer stmt.Close()
	rows, err := stmt.Query(id)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer rows.Close()
	var pks []bakery.PublicKey
	for rows.Next() {
		var b sql.RawBytes
		if err := rows.Scan(&b); err != nil {
			return nil, errgo.Mask(err)
		}
		var pk bakery.PublicKey
		if err := pk.UnmarshalBinary(b); err != nil {
			logger.Errorf("invalid public key in database: %s", err)
			continue
		}
		pks = append(pks, pk)
	}
	return pks, errgo.Mask(rows.Err())
}

func (s *identityStore) getInfoMap(tx *sql.Tx, stmtID stmtID, id string) (map[string][]string, error) {
	stmt := s.driver.Stmt(tx, stmtID)
	defer stmt.Close()
	rows, err := stmt.Query(id)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer rows.Close()
	info := make(map[string][]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, errgo.Mask(err)
		}
		info[k] = append(info[k], v)
	}
	return info, errgo.Mask(rows.Err())
}

// UpdateIdentity implements store.Store.UpdateIdentity.
func (s *identityStore) UpdateIdentity(_ context.Context, identity *store.Identity, update store.Update) (err error) {
	return errgo.Mask(s.withTx(func(tx *sql.Tx) error {
		return s.updateIdentity(tx, identity, update)
	}), errgo.Is(store.ErrDuplicateUsername), errgo.Is(store.ErrNotFound))
}

type updateParams struct {
	// Column contains the name of the column to use to determine the
	// identity to be updated or returned.
	Column string

	// Columns contains the list of columns to be updated or
	// returned.
	Columns []string

	// Args contains the list of argument numbers that will be
	// substituted in when the query is executed.
	Args []int
}

func (s *identityStore) updateIdentity(tx *sql.Tx, identity *store.Identity, update store.Update) error {
	tmpl := tmplUpdateIdentity
	var params updateParams
	args := make([]interface{}, 0, len(update)+1)
	switch {
	case identity.ID != "":
		if _, err := strconv.Atoi(identity.ID); err != nil {
			// By definition if id isn't numeric it won't exist.
			return store.NotFoundError(identity.ID, "", "")
		}
		params.Column = "id"
		args = append(args, identity.ID)
	case identity.ProviderID != "":
		if update[store.Username] == store.Set {
			tmpl = tmplUpsertIdentity
		}
		params.Column = "providerid"
		args = append(args, identity.ProviderID)
	case identity.Username != "":
		params.Column = "username"
		args = append(args, identity.Username)
	default:
		return store.NotFoundError("", "", "")
	}
	for i, op := range update {
		field := store.Field(i)
		if field == store.ProviderID {
			continue
		}
		col := identityColumns[field]
		if col == "" {
			continue
		}
		var arg interface{}
		switch op {
		case store.Clear:
			arg = nil
		case store.Set:
			arg = fieldValue(field, identity)
		default:
			// ignore push and pull as they don't make sense for scalar values.
			continue
		}
		args = append(args, arg)
		params.Columns = append(params.Columns, col)
		params.Args = append(params.Args, len(args))
	}
	if len(params.Columns) == 0 {
		tmpl = tmplIdentityID
	}
	row, err := s.driver.QueryRow(tx, tmpl, params, args...)
	if err != nil {
		return errgo.Notef(err, "cannot update identity")
	}
	if err := row.Scan(&identity.ID); err != nil {
		if errgo.Cause(err) == sql.ErrNoRows {
			return store.NotFoundError(identity.ID, identity.ProviderID, identity.Username)
		}
		if s.driver.isDuplicateFunc(err) {
			return store.DuplicateUsernameError(identity.Username)
		}
		return errgo.Notef(err, "cannot update identity")
	}

	if err := s.updateGroups(tx, identity.ID, update[store.Groups], identity.Groups); err != nil {
		return errgo.Notef(err, "cannot update identity")
	}
	if err := s.updatePublicKeys(tx, identity.ID, update[store.PublicKeys], identity.PublicKeys); err != nil {
		return errgo.Notef(err, "cannot update identity")
	}
	for k, vs := range identity.ProviderInfo {
		if err := s.updateProviderInfo(tx, identity.ID, k, update[store.ProviderInfo], vs); err != nil {
			return errgo.Notef(err, "cannot update identity")
		}
	}
	for k, vs := range identity.ExtraInfo {
		if err := s.updateExtraInfo(tx, identity.ID, k, update[store.ExtraInfo], vs); err != nil {
			return errgo.Notef(err, "cannot update identity")
		}
	}

	return nil
}

type updateSetParams struct {
	Table  string
	Key    bool
	Values int
}

func (s *identityStore) updateSet(tx *sql.Tx, table, id, key string, op store.Operation, values []interface{}) error {
	if op == store.NoUpdate {
		return nil
	}
	params := updateSetParams{
		Table:  table,
		Key:    key != "",
		Values: len(values),
	}
	if op == store.Clear || op == store.Set {
		args := []interface{}{id}
		if key != "" {
			args = append(args, key)
		}
		if _, err := s.driver.Exec(tx, tmplClearIdentitySet, params, args...); err != nil {
			return errgo.Mask(err)
		}
	}
	if len(values) == 0 {
		return nil
	}

	var tmpl tmplID
	var args []interface{}
	switch op {
	case store.Set, store.Push:
		tmpl = tmplPushIdentitySet
		args = make([]interface{}, 0, 3*len(values))
		for _, v := range values {
			args = append(args, id)
			if key != "" {
				args = append(args, key)
			}
			args = append(args, v)
		}
	case store.Pull:
		tmpl = tmplPullIdentitySet
		args = make([]interface{}, 0, len(values)+2)
		args = append(args, id)
		if key != "" {
			args = append(args, key)
		}
		for _, v := range values {
			args = append(args, v)
		}
	default:
		return nil
	}
	if _, err := s.driver.Exec(tx, tmpl, params, args...); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

func (s *identityStore) updateGroups(tx *sql.Tx, id string, op store.Operation, groups []string) error {
	values := make([]interface{}, len(groups))
	for i, g := range groups {
		values[i] = g
	}
	return errgo.Mask(s.updateSet(tx, "identity_groups", id, "", op, values))
}

func (s *identityStore) updatePublicKeys(tx *sql.Tx, id string, op store.Operation, pks []bakery.PublicKey) error {
	values := make([]interface{}, len(pks))
	for i := range pks {
		// MarshalBinary for a key does not return an error.
		values[i], _ = pks[i].MarshalBinary()
	}
	return errgo.Mask(s.updateSet(tx, "identity_publickeys", id, "", op, values))
}

func (s *identityStore) updateProviderInfo(tx *sql.Tx, id, key string, op store.Operation, values []string) error {
	vals := make([]interface{}, len(values))
	for i, v := range values {
		vals[i] = v
	}
	return errgo.Mask(s.updateSet(tx, "identity_providerinfo", id, key, op, vals))
}

func (s *identityStore) updateExtraInfo(tx *sql.Tx, id, key string, op store.Operation, values []string) error {
	vals := make([]interface{}, len(values))
	for i, v := range values {
		vals[i] = v
	}
	return errgo.Mask(s.updateSet(tx, "identity_extrainfo", id, key, op, vals))
}

type nullTime struct {
	Time  time.Time
	Valid bool
}

// Scan implements sql.Scanner.
func (n *nullTime) Scan(src interface{}) error {
	if src == nil {
		n.Time = time.Time{}
		n.Valid = false
		return nil
	}
	if t, ok := src.(time.Time); ok {
		n.Time = t
		n.Valid = true
		return nil
	}
	return errgo.Newf("unsupported Scan, storing driver.Value type %T into type %T", src, n)
}

// Value implements sqldriver.Valuer.
func (n nullTime) Value() (sqldriver.Value, error) {
	if n.Valid {
		return n.Time, nil
	}
	return nil, nil
}

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanIdentity(s scanner, identity *store.Identity) error {
	var name, email sql.NullString
	var lastLogin, lastDischarge nullTime
	err := s.Scan(
		&identity.ID,
		&identity.ProviderID,
		&identity.Username,
		&name,
		&email,
		&lastLogin,
		&lastDischarge,
	)
	if err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	identity.Name = name.String
	identity.Email = email.String
	identity.LastLogin = lastLogin.Time
	identity.LastDischarge = lastDischarge.Time
	return nil
}
