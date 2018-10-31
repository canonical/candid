package mgostore_test

import (
	"os"

	"github.com/juju/mgotest"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/candid/store"
	"github.com/CanonicalLtd/candid/store/mgostore"
	storetesting "github.com/CanonicalLtd/candid/store/testing"
)

var _ = gc.Suite(&configSuite{})

type configSuite struct {
	db  *mgotest.Database
	url string
}

func (s *configSuite) SetUpTest(c *gc.C) {
	var err error
	s.db, err = mgotest.New()
	if errgo.Cause(err) == mgotest.ErrDisabled {
		c.Skip("mgotest disabled")
	}
	c.Assert(err, gc.Equals, nil)
	s.url = os.Getenv("MGOCONNECTIONSTRING")
	if s.url == "" {
		s.url = "localhost"
	}
}

func (s *configSuite) TearDownTest(c *gc.C) {
	if s.db != nil {
		s.db.Close()
	}
}

func (s *configSuite) TestUnmarshal(c *gc.C) {
	storetesting.TestUnmarshal(c, `
storage:
    type: mongodb
    address: `+s.url+`
    database: `+s.db.Name+`
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

func (s *configSuite) TestUnmarshalWithoutDatabase(c *gc.C) {
	configData := `
storage:
    type: mongodb
    address: ` + s.url + `
`
	var cfg struct {
		Storage *store.Config `yaml:"storage"`
	}
	err := yaml.Unmarshal([]byte(configData), &cfg)
	c.Assert(err, gc.Equals, nil)

	p, ok := cfg.Storage.BackendFactory.(mgostore.Params)
	c.Assert(ok, gc.Equals, true)
	c.Assert(p.Database, gc.Equals, "candid")
}
