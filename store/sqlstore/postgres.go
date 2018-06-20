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

CREATE TABLE IF NOT EXISTS meetings ( 
	id TEXT NOT NULL PRIMARY KEY,
	address TEXT NOT NULL,
	created TIMESTAMP WITH TIME ZONE NOT NULL
);
`

var postgresTmpls = [numTmpl]string{
	tmplIdentityFrom: `
		SELECT id, providerid, username, name, email, lastlogin, lastdischarge
		FROM identities
		WHERE {{.Column}}={{.Identity | .Arg}}`,
	tmplSelectIdentitySet: `
		SELECT {{if .Key}}key, {{end}}value FROM {{.Table}} 
		WHERE identity={{.Identity | .Arg}}`,
	tmplFindIdentities: `
		SELECT id, providerid, username, name, email, lastlogin, lastdischarge FROM identities
		{{if .Where}}WHERE{{range $i, $w := .Where}}{{if gt $i 0}} AND{{end}} {{$w.Column}}{{$w.Comparison}}{{$w.Value | $.Arg}}{{end}}{{end}}
		{{if .Sort}}ORDER BY {{join .Sort ", "}}{{end}}
		{{if gt .Limit 0}}LIMIT {{.Limit}}{{end}}
		{{if gt .Skip 0}}OFFSET {{.Skip}}{{end}}`,
	tmplUpdateIdentity: `
		UPDATE identities
		SET {{range $i, $u := .Updates}}{{if gt $i 0}}, {{end}} {{$u.Column}}={{$u.Value | $.Arg}}{{end}}
		WHERE {{.Column}}={{.Identity | .Arg}}
		RETURNING id`,
	tmplIdentityID: `
		SELECT id FROM identities
		WHERE {{.Column}}={{.Identity | .Arg}}`,
	tmplUpsertIdentity: `
		INSERT INTO identities (providerid{{range .Updates}}, {{.Column}}{{end}})
		VALUES ({{.Identity | .Arg}}{{range .Updates}}, {{.Value | $.Arg}}{{end}})
		ON CONFLICT (providerid) DO UPDATE 
		SET{{range $i, $u := .Updates}}{{if gt $i 0}}, {{end}} {{$u.Column}}={{$u.Value | $.Arg}}{{end}}
		WHERE identities.providerid={{.Identity | .Arg}}
		RETURNING id`,
	tmplClearIdentitySet: `
		DELETE FROM {{.Table}}
		WHERE identity={{.ID | .Arg}}{{if .Key}} AND key={{.Key | .Arg}}{{end}}`,
	tmplPushIdentitySet: `
		INSERT INTO {{.Table}} (identity, {{if .Key}}key, {{end}}value)
		VALUES {{range $i, $v := .Values}}{{if gt $i 0}}, {{end}}({{$.ID | $.Arg}}, {{if $.Key}}{{$.Key | $.Arg}}, {{end}}{{$v | $.Arg}}){{end}}
		ON CONFLICT (identity, {{if .Key}}key, {{end}}value) DO NOTHING`,
	tmplPullIdentitySet: `
		DELETE FROM {{.Table}}
		WHERE identity={{.ID | $.Arg}}{{if .Key}} AND key={{.Key | $.Arg}}{{end}}
		AND value IN ({{range $i, $v := .Values}}{{if gt $i 0}}, {{end}}{{$v | $.Arg}}{{end}})`,
	tmplGetProviderData: `
		SELECT value FROM provider_data
		WHERE provider={{.Provider | .Arg}} AND key={{.Key | .Arg}} AND (expire IS NULL OR expire > now())`,
	tmplGetProviderDataForUpdate: `
		SELECT value FROM provider_data
		WHERE provider={{.Provider | .Arg}} AND key={{.Key | .Arg}} AND (expire IS NULL OR expire > now())
		FOR UPDATE`,
	tmplInsertProviderData: `
		INSERT INTO provider_data (provider, key, value, expire)
		VALUES ({{.Provider | .Arg}}, {{.Key | .Arg}}, {{.Value | .Arg}}, {{.Expire | .Arg}})
		{{if .Update}}ON CONFLICT (provider, key) DO UPDATE
		SET value={{.Value | .Arg}}, expire={{.Expire | .Arg}}{{end}}`,
	tmplGetMeeting: `
		SELECT address, created FROM meetings
		WHERE id={{.ID | .Arg}}`,
	tmplPutMeeting: `
		INSERT INTO meetings (id, address, created)
		VALUES ({{.ID | .Arg}}, {{.Address | .Arg}}, {{.Time | .Arg}})`,
	tmplFindMeetings: `
		SELECT id FROM meetings
		WHERE created < {{.Time | .Arg}}{{if .Address}} AND address={{.Address | .Arg}}{{end}}`,
	tmplRemoveMeetings: `
		DELETE FROM meetings
		WHERE id IN({{range $i, $id := .IDs}}{{if gt $i 0}}, {{end}}{{$id | $.Arg}}{{end}})`,
}

// newPostgresDriver creates a postgres driver using the given DB.
func newPostgresDriver(db *sql.DB) (*driver, error) {
	_, err := db.Exec(postgresInit)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	d := &driver{
		argBuilderFunc: func() argBuilder {
			return &postgresArgBuilder{}
		},
		isDuplicateFunc: postgresIsDuplicate,
	}
	for i, t := range postgresTmpls {
		if err := d.parseTemplate(tmplID(i), t); err != nil {
			return nil, errgo.Notef(err, "cannot parse template %v", t)
		}
	}
	return d, nil
}

func postgresIsDuplicate(err error) bool {
	if pqerr, ok := err.(*pq.Error); ok && pqerr.Code.Name() == "unique_violation" {
		return true
	}
	return false
}

// postgresArgBuilder implements an argBuilder that produces placeholders
// in the the "$n" format.
type postgresArgBuilder struct {
	args_ []interface{}
}

// Arg implements argbuilder.Arg.
func (b *postgresArgBuilder) Arg(a interface{}) string {
	b.args_ = append(b.args_, a)
	return fmt.Sprintf("$%d", len(b.args_))
}

// args implements argbuilder.args.
func (b *postgresArgBuilder) args() []interface{} {
	return b.args_
}
