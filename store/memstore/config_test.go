package memstore_test

import (
	storetesting "github.com/CanonicalLtd/candid/store/testing"
	gc "gopkg.in/check.v1"
)

var _ = gc.Suite(&configSuite{})

type configSuite struct{}

func (s *configSuite) TestUnmarshal(c *gc.C) {
	storetesting.TestUnmarshal(c, `
storage:
    type: memory
`)
}
