// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package agent_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/candid/config"
	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/idp/agent"
)

func TestConfig(t *testing.T) {
	c := qt.New(t)
	configYaml := `
identity-providers:
 - type: agent
`
	var conf config.Config
	err := yaml.Unmarshal([]byte(configYaml), &conf)
	c.Assert(err, qt.Equals, nil)
	c.Assert(conf.IdentityProviders, qt.HasLen, 1)
	c.Assert(conf.IdentityProviders[0].Name(), qt.Equals, "agent")
}

func TestName(t *testing.T) {
	c := qt.New(t)
	c.Assert(agent.IdentityProvider.Name(), qt.Equals, "agent")
}

func TestDescription(t *testing.T) {
	c := qt.New(t)
	c.Assert(agent.IdentityProvider.Description(), qt.Equals, "")
}

func TestInteractive(t *testing.T) {
	c := qt.New(t)
	c.Assert(agent.IdentityProvider.Interactive(), qt.Equals, false)
}

func TestURL(t *testing.T) {
	c := qt.New(t)
	u := agent.IdentityProvider.URL("1")
	c.Assert(u, qt.Equals, "")
}

func TestInitProducesError(t *testing.T) {
	c := qt.New(t)
	err := agent.IdentityProvider.Init(nil, idp.InitParams{})
	c.Assert(err, qt.ErrorMatches, "agent login IDP no longer supported")
}
