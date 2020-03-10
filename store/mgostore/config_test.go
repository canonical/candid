package mgostore_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"gopkg.in/yaml.v2"

	"github.com/canonical/candid/store"
	"github.com/canonical/candid/store/mgostore"
	"github.com/canonical/candid/store/storetest"
)

func TestUnmarshal(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	f := newFixture(c)
	storetest.TestUnmarshal(c, `
storage:
    type: mongodb
    address: `+f.connStr+`
    database: `+f.db.Name+`
`)
}

func TestUnmarshalWithNoAddress(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	configData := `
storage:
    type: mongodb
`
	var cfg struct {
		Storage *store.Config `yaml:"storage"`
	}
	err := yaml.Unmarshal([]byte(configData), &cfg)
	c.Assert(err, qt.ErrorMatches, `cannot unmarshal mongodb configuration: no address field in mongodb storage configuration`)
}

func TestUnmarshalWithoutDatabase(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	f := newFixture(c)
	configData := `
storage:
    type: mongodb
    address: ` + f.connStr + `
`
	var cfg struct {
		Storage *store.Config `yaml:"storage"`
	}
	err := yaml.Unmarshal([]byte(configData), &cfg)
	c.Assert(err, qt.Equals, nil)

	p, ok := cfg.Storage.BackendFactory.(mgostore.Params)
	c.Assert(ok, qt.Equals, true)
	c.Assert(p.Database, qt.Equals, "candid")
}
