package sqlstore_test

import (
	storetesting "github.com/CanonicalLtd/candid/store/testing"
	"github.com/juju/postgrestest"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
)

var _ = gc.Suite(&configSuite{})

type configSuite struct {
	pg *postgrestest.DB
}

func (s *configSuite) SetUpTest(c *gc.C) {
	pg, err := postgrestest.New()
	if errgo.Cause(err) == postgrestest.ErrDisabled {
		c.Skip(err.Error())
		return
	}
	c.Assert(err, gc.Equals, nil)
	s.pg = pg
}

func (s *configSuite) TearDownTest(c *gc.C) {
	if s.pg != nil {
		s.pg.Close()
	}
}

func (s *configSuite) TestUnmarshal(c *gc.C) {
	storetesting.TestUnmarshal(c, `
storage:
    type: postgres
    connection-string: 'search_path=`+s.pg.Schema()+`'
`)
}
