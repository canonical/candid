// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package azure_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"gopkg.in/yaml.v2"

	"github.com/CanonicalLtd/candid/config"
)

var configTests = []struct {
	about       string
	yaml        string
	expectError string
}{{
	about: "good config",
	yaml: `
identity-providers:
 - type: azure
   client-id: client-001
   client-secret: secret-001
`,
}, {
	about: "no client-id",
	yaml: `
identity-providers:
 - type: azure
   client-secret: secret-001
`,
	expectError: `cannot unmarshal azure configuration: client-id not specified`,
}, {
	about: "no client-secret",
	yaml: `
identity-providers:
 - type: azure
   client-id: client-001
`,
	expectError: `cannot unmarshal azure configuration: client-secret not specified`,
}}

func TestConfig(t *testing.T) {
	c := qt.New(t)
	for _, test := range configTests {
		c.Run(test.about, func(c *qt.C) {
			var conf config.Config
			err := yaml.Unmarshal([]byte(test.yaml), &conf)
			if test.expectError != "" {
				c.Assert(err, qt.ErrorMatches, test.expectError)
				return
			}
			c.Assert(err, qt.Equals, nil)
			c.Assert(conf.IdentityProviders, qt.HasLen, 1)
			c.Assert(conf.IdentityProviders[0].Name(), qt.Equals, "azure")
		})
	}
}
