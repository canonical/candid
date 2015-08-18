// Copyright 2014 Canonical Ltd.

package config_test

import (
	"io/ioutil"
	"path"
	"testing"
	"time"

	jujutesting "github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/config"
	"github.com/CanonicalLtd/blues-identity/idp"
)

func TestPackage(t *testing.T) {
	gc.TestingT(t)
}

type configSuite struct {
	jujutesting.IsolationSuite
}

var _ = gc.Suite(&configSuite{})

const testConfig = `
mongo-addr: localhost:23456
api-addr: 1.2.3.4:5678
foo: 1
bar: false
auth-username: myuser
auth-password: mypasswd
private-key: 8PjzjakvIlh3BVFKe8axinRDutF6EDIfjtuf4+JaNow=
public-key: CIdWcEUN+0OZnKW9KwruRQnQDY/qqzVdD30CijwiWCk=
location: http://foo.com:1234
max-mgo-sessions: 10
request-timeout: 500ms
identity-providers:
 - type: usso
 - type: keystone
   name: ks1
   url: http://example.com/keystone
`

func (s *configSuite) readConfig(c *gc.C, content string) (*config.Config, error) {
	// Write the configuration content to file.
	path := path.Join(c.MkDir(), "config.yaml")
	err := ioutil.WriteFile(path, []byte(content), 0666)
	c.Assert(err, gc.IsNil)

	// Read the configuration.
	return config.Read(path)
}

func (s *configSuite) TestRead(c *gc.C) {
	conf, err := s.readConfig(c, testConfig)
	c.Assert(err, gc.IsNil)
	c.Assert(conf, jc.DeepEquals, &config.Config{
		MongoAddr:      "localhost:23456",
		APIAddr:        "1.2.3.4:5678",
		AuthUsername:   "myuser",
		AuthPassword:   "mypasswd",
		PrivateKey:     "8PjzjakvIlh3BVFKe8axinRDutF6EDIfjtuf4+JaNow=",
		PublicKey:      "CIdWcEUN+0OZnKW9KwruRQnQDY/qqzVdD30CijwiWCk=",
		Location:       "http://foo.com:1234",
		MaxMgoSessions: 10,
		RequestTimeout: config.DurationString{Duration: 500 * time.Millisecond},
		IdentityProviders: []idp.IdentityProvider{
			idp.UbuntuSSOIdentityProvider,
			idp.KeystoneIdentityProvider(&idp.KeystoneParams{
				Name: "ks1",
				URL:  "http://example.com/keystone",
			}),
		},
	})
}

func (s *configSuite) TestReadErrorNotFound(c *gc.C) {
	cfg, err := config.Read(path.Join(c.MkDir(), "no-such-file.yaml"))
	c.Assert(err, gc.ErrorMatches, ".* no such file or directory")
	c.Assert(cfg, gc.IsNil)
}

func (s *configSuite) TestReadErrorEmpty(c *gc.C) {
	cfg, err := s.readConfig(c, "")
	c.Assert(err, gc.ErrorMatches, "missing fields mongo-addr, api-addr, auth-username, auth-password, private-key, public-key, location, max-mgo-sessions in config file")
	c.Assert(cfg, gc.IsNil)
}

func (s *configSuite) TestReadErrorInvalidYAML(c *gc.C) {
	cfg, err := s.readConfig(c, ":")
	c.Assert(err, gc.ErrorMatches, "cannot parse .*: yaml: did not find expected key")
	c.Assert(cfg, gc.IsNil)
}
