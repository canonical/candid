// Copyright 2016 Canonical Ltd.

package admincmd_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/testing/filetesting"
	gc "gopkg.in/check.v1"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"

	"github.com/CanonicalLtd/blues-identity/cmd/user-admin/internal/admincmd"
)

const testAgent = `{"username":"admin@idm","public_key":"5Htoc1jTiIlSDxUW+9ZIrSXEarH1XU/SRJNNLRvgN1k=","private_key":"YwBfLQvzPwuFEeqGUprc8zYk3iMi1VqdRmklZdF++w8="}`
const testInvalidAgent = `{"username":"admin@idm","public_key":"\xff5Htoc1jTiIlSDxUW+9ZIrSXEarH1XU/SRJNNLRvgN1k=","private_key":"YwBfLQvzPwuFEeqGUprc8zYk3iMi1VqdRmklZdF++w8="}`
const testAgentCookie = `{"username":"admin@idm","public_key":"5Htoc1jTiIlSDxUW+9ZIrSXEarH1XU/SRJNNLRvgN1k="}`

type agentSuite struct {
	key *bakery.KeyPair
}

var _ = gc.Suite(&agentSuite{})

func (s *agentSuite) SetUpSuite(c *gc.C) {
	var err error
	s.key, err = bakery.GenerateKey()
	c.Assert(err, gc.Equals, nil)
}

var readTests = []struct {
	about            string
	data             string
	expectError      string
	expectUser       string
	expectPrivateKey bool
}{{
	about:            "full agent",
	data:             testAgent,
	expectUser:       "admin@idm",
	expectPrivateKey: true,
}, {
	about:      "no private key",
	data:       testAgentCookie,
	expectUser: "admin@idm",
}}

func (s *agentSuite) TestRead(c *gc.C) {
	for i, test := range readTests {
		c.Logf("test %d. %s", i, test.about)
		r := strings.NewReader(test.data)
		a, err := admincmd.Read(r)
		if test.expectError != "" {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			c.Assert(a, jc.DeepEquals, admincmd.Agent{})
			continue
		}
		c.Assert(err, gc.Equals, nil)
		c.Assert(a.Username, jc.DeepEquals, test.expectUser)
		c.Assert(a.PublicKey, gc.Not(gc.IsNil))
		if test.expectPrivateKey {
			c.Assert(a.PrivateKey, gc.Not(gc.IsNil))
		} else {
			c.Assert(a.PrivateKey, gc.IsNil)
		}
	}
}

func (s *agentSuite) TestReadError(c *gc.C) {
	stub := new(testing.Stub)
	r := filetesting.NewStubReader(stub, "")
	stub.SetErrors(errgo.New("test error"))
	a, err := admincmd.Read(r)
	c.Assert(err, gc.ErrorMatches, `test error`)
	c.Assert(a, jc.DeepEquals, admincmd.Agent{})
}

func (s *agentSuite) TestLoad(c *gc.C) {
	path := c.MkDir()
	fn := filepath.Join(path, "test.agent")
	f, err := os.Create(fn)
	c.Assert(err, gc.Equals, nil)
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s", testAgent)
	c.Assert(err, gc.Equals, nil)
	a, err := admincmd.Load(fn)
	c.Assert(err, gc.Equals, nil)
	c.Assert(a.Username, jc.DeepEquals, "admin@idm")
	c.Assert(a.PublicKey, gc.Not(gc.IsNil))
	c.Assert(a.PrivateKey, gc.Not(gc.IsNil))
}

func (s *agentSuite) TestLoadNoFile(c *gc.C) {
	path := c.MkDir()
	fn := filepath.Join(path, "test.agent")
	a, err := admincmd.Load(fn)
	c.Assert(err, gc.ErrorMatches, "open .*/test.agent: no such file or directory")
	c.Assert(a, jc.DeepEquals, admincmd.Agent{})
}

func (s *agentSuite) TestLoadBadFile(c *gc.C) {
	path := c.MkDir()
	fn := filepath.Join(path, "test.agent")
	f, err := os.Create(fn)
	c.Assert(err, gc.Equals, nil)
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s", testInvalidAgent)
	c.Assert(err, gc.Equals, nil)
	a, err := admincmd.Load(fn)
	c.Assert(err, gc.ErrorMatches, `cannot load agent from .*/test.agent: invalid character 'x' in string escape code`)
	c.Assert(a, jc.DeepEquals, admincmd.Agent{})
}

func (s *agentSuite) TestWrite(c *gc.C) {
	a := admincmd.Agent{
		Username:   "agent@bob",
		PublicKey:  &s.key.Public,
		PrivateKey: &s.key.Private,
	}
	buf := new(bytes.Buffer)
	err := admincmd.Write(buf, a)
	c.Assert(err, gc.Equals, nil)
	a1, err := admincmd.Read(buf)
	c.Assert(err, gc.Equals, nil)
	// Check that it round tripped properly
	c.Assert(a1, jc.DeepEquals, a)
}

func (s *agentSuite) TestWriteNoPrivateKey(c *gc.C) {
	a := admincmd.Agent{
		Username:  "agent@bob",
		PublicKey: &s.key.Public,
	}
	buf := new(bytes.Buffer)
	err := admincmd.Write(buf, a)
	c.Assert(err, gc.Equals, nil)
	var m map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &m)
	c.Assert(err, gc.Equals, nil)
	c.Assert(m["username"], gc.Equals, "agent@bob")
	c.Assert(m["public_key"], gc.Equals, s.key.Public.String())
	_, ok := m["private_key"]
	c.Assert(ok, gc.Equals, false)
}

func (s *agentSuite) TestWriteError(c *gc.C) {
	stub := new(testing.Stub)
	w, _ := filetesting.NewStubWriter(stub)
	stub.SetErrors(errgo.New("test error"))
	a := admincmd.Agent{
		Username:  "agent@bob",
		PublicKey: &s.key.Public,
	}
	err := admincmd.Write(w, a)
	c.Assert(err, gc.ErrorMatches, `test error`)
}
