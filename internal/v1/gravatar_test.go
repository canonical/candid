// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package v1_test

import (
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/candid/internal/v1"
)

func TestGravatarHash(t *testing.T) {
	c := qt.New(t)

	c.Assert(v1.GravatarHash("myemail@domain.com"), qt.Equals, v1.GravatarHash("myemail@domain.com "))
	c.Assert(v1.GravatarHash("myemail@domain.com"), qt.Equals, v1.GravatarHash(" myemail@domain.com"))
	c.Assert(v1.GravatarHash("myemail@domain.com"), qt.Equals, v1.GravatarHash("MYEMAIL@domain.com"))
	c.Assert(v1.GravatarHash("jbloggs3@example.com"), qt.Equals, "21e89fe03e3a3cc553933f99eb442d94")
}
