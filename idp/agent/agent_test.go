// Copyright 2015 Canonical Ltd.

package agent_test

import (
	gc "gopkg.in/check.v1"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/idp/agent"
)

type agentSuite struct{}

var _ = gc.Suite(&agentSuite{})

func (s *agentSuite) TestConfig(c *gc.C) {
	configYaml := `
identity-providers:
 - type: agent
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(configYaml), &conf)
	c.Assert(err, gc.IsNil)
	c.Assert(conf.IdentityProviders, gc.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), gc.Equals, "agent")
}

func (s *agentSuite) TestName(c *gc.C) {
	c.Assert(agent.IdentityProvider.Name(), gc.Equals, "agent")
}

func (s *agentSuite) TestDescription(c *gc.C) {
	c.Assert(agent.IdentityProvider.Description(), gc.Equals, "")
}

func (s *agentSuite) TestInteractive(c *gc.C) {
	c.Assert(agent.IdentityProvider.Interactive(), gc.Equals, false)
}

func (s *agentSuite) TestURL(c *gc.C) {
	u := agent.IdentityProvider.URL("1")
	c.Assert(u, gc.Equals, "")
}

func (s *agentSuite) TestInitProducesError(c *gc.C) {
	err := agent.IdentityProvider.Init(nil, idp.InitParams{})
	c.Assert(err, gc.ErrorMatches, "agent login IDP no longer supported")
}
