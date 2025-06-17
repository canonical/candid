package mgostore

import (
	mgo "github.com/juju/mgo/v2"
	errgo "gopkg.in/errgo.v1"

	"github.com/canonical/candid/store"
)

// Params holds the specification for the parameters
// used in the config file.
type Params struct {
	// Address holds the address of the MongoDB
	// server to connect to, in host:port form.
	Address string `yaml:"address"`

	// Database holds the database name to use.
	// If this is empty, "candid" will be used.
	Database string `yaml:"database"`
}

func init() {
	store.Register("mongodb", unmarshalBackend)
}

func unmarshalBackend(unmarshal func(interface{}) error) (store.BackendFactory, error) {
	var p Params
	if err := unmarshal(&p); err != nil {
		return nil, errgo.Mask(err)
	}
	if p.Address == "" {
		return nil, errgo.Newf("no address field in mongodb storage configuration")
	}
	if p.Database == "" {
		p.Database = "candid"
	}
	return p, nil
}

// NewBackend implements store.BackendFactory.
func (p Params) NewBackend() (store.Backend, error) {
	logger.Infof("connecting to mongo")
	session, err := mgo.Dial(p.Address)
	if err != nil {
		return nil, errgo.Notef(err, "cannot dial mongo at %q", p.Address)
	}
	defer session.Close()
	db := session.DB(p.Database)
	return NewBackend(db)
}
