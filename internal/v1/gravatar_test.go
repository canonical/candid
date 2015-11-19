// Copyright 2015 Canonical Ltd.

package v1_test

import (
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/v1"
)

type gravatarSuite struct{}

var _ = gc.Suite(&gravatarSuite{})

func (*gravatarSuite) TestGravatarHash(c *gc.C) {
	c.Assert(v1.GravatarHash("myemail@domain.com"), gc.Equals, v1.GravatarHash("myemail@domain.com "))
	c.Assert(v1.GravatarHash("myemail@domain.com"), gc.Equals, v1.GravatarHash(" myemail@domain.com"))
	c.Assert(v1.GravatarHash("myemail@domain.com"), gc.Equals, v1.GravatarHash("MYEMAIL@domain.com"))
	c.Assert(v1.GravatarHash("jbloggs3@example.com"), gc.Equals, "21e89fe03e3a3cc553933f99eb442d94")
}
