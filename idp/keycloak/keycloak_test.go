// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keycloak_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"gopkg.in/yaml.v2"

	"github.com/canonical/candid/config"
)

var configTests = []struct {
	about				string
	yaml				string
	expectError string
}{{
	about: "good config",
	yaml: `
identity-providers:
 - type: keycloak 
	 client-id: client-001
	 client-secret: secret-001
	 keycloak-realm: https://example.com/auth/realms/example
	 domain: example
`,
}, {
	about: "no client-id",
	yaml: `
identity-providers:
 - type: keycloak 
	 client-secret: secret-001
	 keycloak-realm: https://example.com/auth/realms/example
`,
	expectError: `cannot unmarshal keycloak configuration: client-id not specified`,
}, {
	about: "no client-secret",
	yaml: `
identity-providers:
 - type: keycloak 
	 client-id: client-001
	 keycloak-realm: https://example.com/auth/realms/example
`,
	expectError: `cannot unmarshal keycloak configuration: client-secret not specified`,
},{
	about: "no keycloak-realm",
	yaml: `
identity-providers:
 - type: keycloak
	 client-id: client-001
	 client-secret: secret-001
`,
	expectError: `cannot unmarshal keycloak configuration: keycloak-realm not specified`,
}
}

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
			c.Assert(conf.IdentityProviders[0].Name(), qt.Equals, "keycloak")
		})
	}
}
