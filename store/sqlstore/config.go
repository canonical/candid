package sqlstore

import (
	"database/sql"

	errgo "gopkg.in/errgo.v1"

	"github.com/canonical/candid/store"
)

// Params holds the specification for the parameters
// used in the config file.
type Params struct {
	ConnectionString string `yaml:"connection-string"`
}

func init() {
	store.Register("postgres", unmarshalBackend)
}

func unmarshalBackend(unmarshal func(interface{}) error) (store.BackendFactory, error) {
	var p Params
	if err := unmarshal(&p); err != nil {
		return nil, errgo.Mask(err)
	}
	return p, nil
}

// NewBackend implements store.BackendFactory.
func (p Params) NewBackend() (store.Backend, error) {
	logger.Infof("connecting to postgresql")
	db, err := sql.Open("postgres", p.ConnectionString)
	if err != nil {
		return nil, errgo.Notef(err, "cannot connect to database")
	}
	backend, err := NewBackend("postgres", db)
	if err != nil {
		return nil, errgo.Notef(err, "cannot initialise database")
	}
	return backend, nil
}
