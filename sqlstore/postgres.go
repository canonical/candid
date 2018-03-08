package sqlstore

import (
	"database/sql"
	"fmt"

	"github.com/lib/pq"
	errgo "gopkg.in/errgo.v1"
)

const postgresInit = `
CREATE TABLE IF NOT EXISTS identities ( 
	id SERIAL PRIMARY KEY,
	providerid TEXT UNIQUE NOT NULL,
	username TEXT UNIQUE NOT NULL,
	name TEXT,
	email TEXT,
	lastlogin TIMESTAMP WITH TIME ZONE,
	lastdischarge TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS identity_groups ( 
	identity INTEGER REFERENCES identities NOT NULL,
	value TEXT NOT NULL,
	UNIQUE (identity, value)
);

CREATE TABLE IF NOT EXISTS identity_publickeys ( 
	identity INTEGER REFERENCES identities NOT NULL,
	value BYTEA NOT NULL,
	UNIQUE (identity, value)
);

CREATE TABLE IF NOT EXISTS identity_providerinfo ( 
	identity INTEGER REFERENCES identities NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	UNIQUE (identity, key, value)
);

CREATE TABLE IF NOT EXISTS identity_extrainfo ( 
	identity INTEGER REFERENCES identities NOT NULL,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	UNIQUE (identity, key, value)
);

CREATE TABLE IF NOT EXISTS provider_data ( 
	provider TEXT NOT NULL,
	key TEXT NOT NULL,
	value BYTEA NOT NULL,
	expire TIMESTAMP WITH TIME ZONE,
	UNIQUE (provider, key)
);

CREATE OR REPLACE FUNCTION provider_data_expire_fn() RETURNS trigger
LANGUAGE plpgsql
AS $$
	BEGIN
		DELETE FROM provider_data WHERE expire < NOW();
		RETURN NEW;
	END;
$$;

CREATE INDEX IF NOT EXISTS provider_data_expire ON provider_data (expire);
DROP TRIGGER IF EXISTS provider_data_expire_tr ON provider_data;
CREATE TRIGGER provider_data_expire_tr
   BEFORE INSERT ON provider_data
   EXECUTE PROCEDURE provider_data_expire_fn();
`

var postgresTmpls = [numTmpl]string{
	tmplIdentityFrom: `
		SELECT id, providerid, username, name, email, lastlogin, lastdischarge
		FROM identities
		WHERE {{.Column}}={{parameter 1}}`,
	tmplSelectIdentitySet: `
		SELECT {{if .Key}}key, {{end}}value FROM {{.Table}} 
		WHERE identity={{parameter 1}}`,
	tmplFindIdentities: `
		SELECT id, providerid, username, name, email, lastlogin, lastdischarge FROM identities
		{{if .Where}}WHERE {{join .Where " AND "}}{{end}}
		{{if .Sort}}ORDER BY {{join .Sort ", "}}{{end}}
		{{if gt .Limit 0}}LIMIT {{.Limit}}{{end}}
		{{if gt .Skip 0}}OFFSET {{.Skip}}{{end}}`,
	tmplUpdateIdentity: `
		UPDATE identities
		SET {{range $i, $c := .Columns}}{{if gt $i 0}}, {{end}} {{$c}}={{index $.Args $i | parameter}}{{end}}
		WHERE {{.Column}}={{parameter 1}}
		RETURNING id`,
	tmplIdentityID: `
		SELECT id FROM identities
		WHERE {{.Column}}={{parameter 1}}`,
	tmplUpsertIdentity: `
		INSERT INTO identities (providerid{{range .Columns}}, {{.}}{{end}})
		VALUES ({{parameter 1}}{{range .Args}}, {{parameter .}}{{end}})
		ON CONFLICT (providerid) DO UPDATE 
		SET{{range $i, $c := .Columns}}{{if gt $i 0}}, {{end}} {{$c}}={{index $.Args $i | parameter}}{{end}}
		WHERE identities.providerid={{parameter 1}}
		RETURNING id`,
	tmplClearIdentitySet: `
		DELETE FROM {{.Table}}
		WHERE identity={{parameter 1}}{{if .Key}} AND key={{parameter 2}}{{end}}`,
	tmplPushIdentitySet: `
		INSERT INTO {{.Table}} (identity, {{if .Key}}key, {{end}}value)
		VALUES {{if .Key}}{{values 1 .Values 3}}{{else}}{{values 1 .Values 2}}{{end}}
		ON CONFLICT (identity, {{if .Key}}key, {{end}}value) DO NOTHING`,
	tmplPullIdentitySet: `
		DELETE FROM {{.Table}}
		WHERE identity={{parameter 1}}{{if .Key}} AND key={{parameter 2}}{{end}}
		AND value IN {{if .Key}}{{values 3 1 .Values}}{{else}}{{values 2 1 .Values}}{{end}}`,
	tmplGetProviderData: `
		SELECT value FROM provider_data
		WHERE provider={{parameter 1}} AND key={{parameter 2}} AND (expire IS NULL OR expire > now())`,
	tmplInsertProviderData: `
		INSERT INTO provider_data (provider, key, value, expire)
		VALUES ({{parameter 1}}, {{parameter 2}}, {{parameter 3}}, {{parameter 4}})
		{{if .}}ON CONFLICT (provider, key) DO UPDATE
		SET value={{parameter 3}}, expire={{parameter 4}}{{end}}`,
}

// postgresStmts contains the list of templates and associated parameters
// to use to generate the required prepared statements.
var postgresStmts = [numStmt]struct {
	tmplID tmplID
	params interface{}
}{
	stmtIdentityFromID:         {tmplIdentityFrom, map[string]string{"Column": "id"}},
	stmtIdentityFromProviderID: {tmplIdentityFrom, map[string]string{"Column": "providerid"}},
	stmtIdentityFromUsername:   {tmplIdentityFrom, map[string]string{"Column": "username"}},
	stmtGroups:                 {tmplSelectIdentitySet, updateSetParams{Table: "identity_groups"}},
	stmtPublicKeys:             {tmplSelectIdentitySet, updateSetParams{Table: "identity_publickeys"}},
	stmtProviderInfo:           {tmplSelectIdentitySet, updateSetParams{Table: "identity_providerinfo", Key: true}},
	stmtExtraInfo:              {tmplSelectIdentitySet, updateSetParams{Table: "identity_extrainfo", Key: true}},
	stmtGetProviderData:        {tmplGetProviderData, nil},
	stmtSetProviderData:        {tmplInsertProviderData, true},
	stmtAddProviderData:        {tmplInsertProviderData, false},
}

// newPostgresDriver creates a postgres driver using the given DB.
func newPostgresDriver(db *sql.DB) (*driver, error) {
	_, err := db.Exec(postgresInit)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	d := &driver{
		parameterFunc:   postgresParameter,
		isDuplicateFunc: postgresIsDuplicate,
	}
	for i, t := range postgresTmpls {
		if err := d.parseTemplate(tmplID(i), t); err != nil {
			return nil, errgo.Notef(err, "cannot parse template %v", i)
		}
	}
	for i, s := range postgresStmts {
		if err := d.Prepare(db, stmtID(i), s.tmplID, s.params); err != nil {
			return nil, errgo.Notef(err, "cannot prepare statement %v", i)
		}
	}
	return d, nil
}

func postgresParameter(n int) string {
	return fmt.Sprintf("$%d", n)
}

func postgresIsDuplicate(err error) bool {
	if pqerr, ok := err.(*pq.Error); ok && pqerr.Code.Name() == "unique_violation" {
		return true
	}
	return false
}
