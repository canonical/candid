package sqlstore

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"strconv"
	"time"

	"github.com/juju/loggo"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/canonical/candid/store"
)

var logger = loggo.GetLogger("candid.sqlstore")

var identityColumns = [store.NumFields]string{
	store.ProviderID:    "providerid",
	store.Username:      "username",
	store.Name:          "name",
	store.Email:         "email",
	store.LastLogin:     "lastlogin",
	store.LastDischarge: "lastdischarge",
	store.Owner:         "owner",
}

type identityStore struct {
	*backend
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

type identityFromParams struct {
	argBuilder

	Column   string
	Identity interface{}
}

func (s *identityStore) identity(tx *sql.Tx, identity *store.Identity) error {
	params := &identityFromParams{
		argBuilder: s.driver.argBuilderFunc(),
	}
	switch {
	case identity.ID != "":
		params.Column = "id"
		params.Identity = identity.ID
	case identity.ProviderID != "":
		params.Column = "providerid"
		params.Identity = identity.ProviderID
	case identity.Username != "":
		params.Column = "username"
		params.Identity = identity.Username
	default:
		return store.NotFoundError("", "", "")
	}
	row, err := s.driver.queryRow(tx, tmplIdentityFrom, params)
	if err != nil {
		return errgo.Mask(err)
	}
	err = scanIdentity(row, identity)
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

type where struct {
	Column     string
	Comparison string
	Value      interface{}
}

type findIdentitiesParams struct {
	argBuilder
	Where []where
	Sort  []string
	Limit int
	Skip  int
}

func (s *identityStore) findIdentities(tx *sql.Tx, ref *store.Identity, filter store.Filter, sort []store.Sort, skip, limit int) ([]store.Identity, error) {
	var wheres []where
	for f, op := range filter {
		col := identityColumns[f]
		cond := comparisons[op]
		if col == "" || cond == "" {
			continue
		}

		wheres = append(wheres, where{col, cond, fieldValue(store.Field(f), ref)})
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

	params := &findIdentitiesParams{
		argBuilder: s.driver.argBuilderFunc(),
		Where:      wheres,
		Sort:       sorts,
		Limit:      limit,
		Skip:       skip,
	}
	rows, err := s.driver.query(tx, tmplFindIdentities, params)
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
		return sql.NullString{id.Name, id.Name != ""}
	case store.Email:
		return sql.NullString{id.Email, id.Email != ""}
	case store.LastLogin:
		return nullTime{id.LastLogin, !id.LastLogin.IsZero()}
	case store.LastDischarge:
		return nullTime{id.LastDischarge, !id.LastDischarge.IsZero()}
	case store.Owner:
		return sql.NullString{string(id.Owner), id.Owner != ""}
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
	identity.ProviderInfo, err = s.getInfoMap(tx, "identity_providerinfo", identity.ID)
	if err != nil {
		return errgo.Mask(err)
	}
	identity.ExtraInfo, err = s.getInfoMap(tx, "identity_extrainfo", identity.ID)
	if err != nil {
		return errgo.Mask(err)
	}
	identity.Credentials, err = s.UserMFACredentials(context.Background(), string(identity.ProviderID))
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

type selectIdentitySetParams struct {
	argBuilder

	Table    string
	Identity string
	Key      bool
}

func (s *identityStore) getGroups(tx *sql.Tx, id string) ([]string, error) {
	params := selectIdentitySetParams{
		argBuilder: s.driver.argBuilderFunc(),
		Table:      "identity_groups",
		Identity:   id,
	}
	rows, err := s.driver.query(tx, tmplSelectIdentitySet, params)
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
	params := selectIdentitySetParams{
		argBuilder: s.driver.argBuilderFunc(),
		Table:      "identity_publickeys",
		Identity:   id,
	}
	rows, err := s.driver.query(tx, tmplSelectIdentitySet, params)
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

func (s *identityStore) getInfoMap(tx *sql.Tx, table string, id string) (map[string][]string, error) {
	params := selectIdentitySetParams{
		argBuilder: s.driver.argBuilderFunc(),
		Table:      table,
		Identity:   id,
		Key:        true,
	}
	rows, err := s.driver.query(tx, tmplSelectIdentitySet, params)
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

type update struct {
	// Column contains the column to set.
	Column string

	// Value contains the value to set the column to.
	Value interface{}
}

type updateIdentityParams struct {
	argBuilder

	// Column contains the name of the column to use to determine the
	// identity to be updated or returned.
	Column string

	// Identity contains the value to match with the identity column
	// above.
	Identity string

	// Updates contains the updates to apply.
	Updates []update
}

func (s *identityStore) updateIdentity(tx *sql.Tx, identity *store.Identity, upd store.Update) error {
	tmpl := tmplUpdateIdentity
	params := updateIdentityParams{
		argBuilder: s.driver.argBuilderFunc(),
	}
	switch {
	case identity.ID != "":
		if _, err := strconv.Atoi(identity.ID); err != nil {
			// By definition if id isn't numeric it won't exist.
			return store.NotFoundError(identity.ID, "", "")
		}
		params.Column = "id"
		params.Identity = identity.ID
	case identity.ProviderID != "":
		if upd[store.Username] == store.Set {
			tmpl = tmplUpsertIdentity
		}
		params.Column = "providerid"
		params.Identity = string(identity.ProviderID)
	case identity.Username != "":
		params.Column = "username"
		params.Identity = identity.Username
	default:
		return store.NotFoundError("", "", "")
	}
	for i, op := range upd {
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
			arg = null{}
		case store.Set:
			arg = fieldValue(field, identity)
		default:
			// ignore push and pull as they don't make sense for scalar values.
			continue
		}
		params.Updates = append(params.Updates, update{col, arg})
	}
	if len(params.Updates) == 0 {
		tmpl = tmplIdentityID
	}
	row, err := s.driver.queryRow(tx, tmpl, params)
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

	if err := s.updateGroups(tx, identity.ID, upd[store.Groups], identity.Groups); err != nil {
		return errgo.Notef(err, "cannot update identity")
	}
	if err := s.updatePublicKeys(tx, identity.ID, upd[store.PublicKeys], identity.PublicKeys); err != nil {
		return errgo.Notef(err, "cannot update identity")
	}
	for k, vs := range identity.ProviderInfo {
		if err := s.updateProviderInfo(tx, identity.ID, k, upd[store.ProviderInfo], vs); err != nil {
			return errgo.Notef(err, "cannot update identity")
		}
	}
	for k, vs := range identity.ExtraInfo {
		if err := s.updateExtraInfo(tx, identity.ID, k, upd[store.ExtraInfo], vs); err != nil {
			return errgo.Notef(err, "cannot update identity")
		}
	}

	return nil
}

type updateSetParams struct {
	argBuilder
	Table  string
	ID     string
	Key    string
	Values []interface{}
}

func (s *identityStore) updateSet(tx *sql.Tx, table, id, key string, op store.Operation, values []interface{}) error {
	if op == store.NoUpdate {
		return nil
	}
	params := &updateSetParams{
		argBuilder: s.driver.argBuilderFunc(),
		Table:      table,
		ID:         id,
		Key:        key,
		Values:     values,
	}
	if op == store.Clear || op == store.Set {
		args := []interface{}{id}
		if key != "" {
			args = append(args, key)
		}
		if _, err := s.driver.exec(tx, tmplClearIdentitySet, params); err != nil {
			return errgo.Mask(err)
		}
	}
	if len(values) == 0 {
		return nil
	}
	// Reset the arg builder
	params.argBuilder = s.driver.argBuilderFunc()
	var tmpl tmplID
	switch op {
	case store.Set, store.Push:
		tmpl = tmplPushIdentitySet
	case store.Pull:
		tmpl = tmplPullIdentitySet
	default:
		return nil
	}
	if _, err := s.driver.exec(tx, tmpl, params); err != nil {
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

// IdentityCounts implements store.IdentityCounts.
func (s *identityStore) IdentityCounts(ctx context.Context) (map[string]int, error) {
	counts := make(map[string]int)
	rows, err := s.driver.query(s.db, tmplIdentityCounts, s.driver.argBuilderFunc())
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer rows.Close()
	for rows.Next() {
		var idp string
		var count int
		if err := rows.Scan(&idp, &count); err != nil {
			return nil, errgo.Mask(err)
		}
		counts[idp] = count
	}
	return counts, errgo.Mask(rows.Err())
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

// null is value that represents a null in the SQL database. Bug
// https://github.com/golang/go/issues/18716 prevents us from using a
// plain nil.
type null struct{}

// Value implements sqldriver.Valuer.
func (n null) Value() (sqldriver.Value, error) {
	return nil, nil
}

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanIdentity(s scanner, identity *store.Identity) error {
	var name, email, owner sql.NullString
	var lastLogin, lastDischarge nullTime
	err := s.Scan(
		&identity.ID,
		&identity.ProviderID,
		&identity.Username,
		&name,
		&email,
		&lastLogin,
		&lastDischarge,
		&owner,
	)
	if err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	identity.Name = name.String
	identity.Email = email.String
	identity.LastLogin = lastLogin.Time
	identity.LastDischarge = lastDischarge.Time
	identity.Owner = store.ProviderIdentity(owner.String)
	return nil
}
