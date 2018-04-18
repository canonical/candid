package sqlstore_test

import (
	"github.com/juju/postgrestest"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/candid/store"
	"github.com/CanonicalLtd/candid/store/sqlstore"
	storetesting "github.com/CanonicalLtd/candid/store/testing"
)

type postgresSuite struct {
	storetesting.StoreSuite
	backend store.Backend
	pg      *postgrestest.DB
}

var _ = gc.Suite(&postgresSuite{})

func (s *postgresSuite) SetUpTest(c *gc.C) {
	var err error
	s.pg, err = postgrestest.New()
	if errgo.Cause(err) == postgrestest.ErrDisabled {
		c.Skip(err.Error())
		return
	}
	c.Assert(err, gc.Equals, nil)
	s.backend, err = sqlstore.NewBackend("postgres", s.pg.DB)
	c.Assert(err, gc.Equals, nil)
	s.Store = s.backend.Store()
	s.StoreSuite.SetUpTest(c)
}

func (s *postgresSuite) TearDownTest(c *gc.C) {
	if s.Store != nil {
		s.StoreSuite.TearDownTest(c)
	}
	if s.backend != nil {
		s.backend.Close()
	}
	if s.pg != nil {
		s.pg.Close()
	}
}

func (s *postgresSuite) TestUpdateIDNotFound(c *gc.C) {
	err := s.Store.UpdateIdentity(
		context.Background(),
		&store.Identity{
			ID:   "1000000",
			Name: "test-user",
		},
		store.Update{
			store.Name: store.Set,
		},
	)
	c.Assert(err, gc.ErrorMatches, `identity "1000000" not found`)
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
}

func (s *postgresSuite) TestUpdateIDEmptyNotFound(c *gc.C) {
	err := s.Store.UpdateIdentity(
		context.Background(),
		&store.Identity{
			ID: "1000000",
		},
		store.Update{},
	)
	c.Assert(err, gc.ErrorMatches, `identity "1000000" not found`)
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
}

func (s *postgresSuite) TestUpdateUsernameEmptyNotFound(c *gc.C) {
	err := s.Store.UpdateIdentity(
		context.Background(),
		&store.Identity{
			Username: "no-user",
		},
		store.Update{},
	)
	c.Assert(err, gc.ErrorMatches, `user no-user not found`)
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
}

func (s *postgresSuite) TestUpdateProviderIDEmptyNotFound(c *gc.C) {
	err := s.Store.UpdateIdentity(
		context.Background(),
		&store.Identity{
			ProviderID: store.MakeProviderIdentity("test", "no-user"),
		},
		store.Update{},
	)
	c.Assert(err, gc.ErrorMatches, `identity "test:no-user" not found`)
	c.Assert(errgo.Cause(err), gc.Equals, store.ErrNotFound)
}

type postgresKeyValueSuite struct {
	storetesting.KeyValueSuite
	backend store.Backend
	pg      *postgrestest.DB
}

var _ = gc.Suite(&postgresKeyValueSuite{})

func (s *postgresKeyValueSuite) SetUpTest(c *gc.C) {
	var err error
	s.pg, err = postgrestest.New()
	if errgo.Cause(err) == postgrestest.ErrDisabled {
		c.Skip(err.Error())
		return
	}
	c.Assert(err, gc.Equals, nil)
	s.backend, err = sqlstore.NewBackend("postgres", s.pg.DB)
	c.Assert(err, gc.Equals, nil)
	s.Store = s.backend.ProviderDataStore()
	s.KeyValueSuite.SetUpTest(c)
}

func (s *postgresKeyValueSuite) TearDownTest(c *gc.C) {
	if s.Store != nil {
		s.KeyValueSuite.TearDownTest(c)
	}
	if s.backend != nil {
		s.backend.Close()
	}
	if s.pg != nil {
		s.pg.Close()
	}
}

type postgresMeetingSuite struct {
	storetesting.MeetingSuite
	backend store.Backend
	pg      *postgrestest.DB
}

var _ = gc.Suite(&postgresMeetingSuite{})

func (s *postgresMeetingSuite) SetUpTest(c *gc.C) {
	var err error
	s.pg, err = postgrestest.New()
	if errgo.Cause(err) == postgrestest.ErrDisabled {
		c.Skip(err.Error())
		return
	}
	c.Assert(err, gc.Equals, nil)
	s.backend, err = sqlstore.NewBackend("postgres", s.pg.DB)
	c.Assert(err, gc.Equals, nil)
	s.Store = s.backend.MeetingStore()
	s.PutAtTimeFunc = sqlstore.PutAtTime
	s.MeetingSuite.SetUpTest(c)
}

func (s *postgresMeetingSuite) TearDownTest(c *gc.C) {
	if s.Store != nil {
		s.MeetingSuite.TearDownTest(c)
	}
	if s.backend != nil {
		s.backend.Close()
	}
	if s.pg != nil {
		s.pg.Close()
	}
}
