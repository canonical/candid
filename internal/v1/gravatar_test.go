package v1

import (
	gc "gopkg.in/check.v1"
)

type gravatarSuite struct{}

var _ = gc.Suite(&gravatarSuite{})

func (*gravatarSuite) TestGravatarHash(c *gc.C) {
	c.Assert(gravatarHash("myemail@domain.com"), gc.Equals, gravatarHash("myemail@domain.com "))
	c.Assert(gravatarHash("myemail@domain.com"), gc.Equals, gravatarHash(" myemail@domain.com"))
	c.Assert(gravatarHash("myemail@domain.com"), gc.Equals, gravatarHash("MYEMAIL@domain.com"))
	c.Assert(gravatarHash("jbloggs3@example.com"), gc.Equals, "21e89fe03e3a3cc553933f99eb442d94")
}
