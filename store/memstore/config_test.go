package memstore_test

import (
	gc "gopkg.in/check.v1"

	storetesting "github.com/CanonicalLtd/candid/store/testing"
)

var _ = gc.Suite(&configSuite{})

type configSuite struct{}

func (s *configSuite) TestUnmarshal(c *gc.C) {
	storetesting.TestUnmarshal(c, `
storage:
    type: memory
`)
}
