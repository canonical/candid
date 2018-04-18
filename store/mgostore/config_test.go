package mgostore_test

import (
	"github.com/CanonicalLtd/candid/store"
	storetesting "github.com/CanonicalLtd/candid/store/testing"
	"github.com/juju/testing"
	gc "gopkg.in/check.v1"
	"gopkg.in/yaml.v2"
)

var _ = gc.Suite(&configSuite{})

type configSuite struct {
	testing.IsolatedMgoSuite
}

func (s *configSuite) TestUnmarshal(c *gc.C) {
	storetesting.TestUnmarshal(c, `
storage:
    type: mongodb
    address: `+testing.MgoServer.Addr()+`
`)
}

func (s *configSuite) TestUnmarshalWithNoAddress(c *gc.C) {
	configData := `
storage:
    type: mongodb
`
	var cfg struct {
		Storage *store.Config `yaml:"storage"`
	}
	err := yaml.Unmarshal([]byte(configData), &cfg)
	c.Assert(err, gc.ErrorMatches, `cannot unmarshal mongodb configuration: no address field in mongodb storage configuration`)
}

func (s *configSuite) TestUnmarshalWithExplicitDatabase(c *gc.C) {
	fooDB := s.Session.DB("foo")
	names, err := fooDB.CollectionNames()
	c.Assert(err, gc.Equals, nil)
	c.Assert(names, gc.HasLen, 0)

	configData := `
storage:
    type: mongodb
    address: ` + testing.MgoServer.Addr() + `
    database: foo
`
	var cfg struct {
		Storage *store.Config `yaml:"storage"`
	}
	err = yaml.Unmarshal([]byte(configData), &cfg)
	c.Assert(err, gc.Equals, nil)

	backend, err := cfg.Storage.NewBackend()
	c.Assert(err, gc.Equals, nil)
	defer backend.Close()

	names, err = fooDB.CollectionNames()
	c.Assert(err, gc.Equals, nil)
	c.Assert(names, gc.Not(gc.HasLen), 0)
}
