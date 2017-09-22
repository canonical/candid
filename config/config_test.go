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
	"gopkg.in/macaroon-bakery.v2/bakery"

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
admin-agent-public-key: dUnC8p9p3nygtE2h92a47Ooq0rXg0fVSm3YBWou5/UQ=
location: http://foo.com:1234
max-mgo-sessions: 10
wait-timeout: 1m
identity-providers:
 - type: usso
 - type: keystone
   name: ks1
   url: http://example.com/keystone
private-addr: localhost
debug-teams:
 - yellow
 - cloud-green
tls-cert: |
  -----BEGIN CERTIFICATE-----
  MIIDLDCCAhQCCQDVXrWn1thP6DANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJH
  QjENMAsGA1UECAwEVGVzdDENMAsGA1UEBwwEVGVzdDENMAsGA1UECgwEVGVzdDEN
  MAsGA1UECwwEVGVzdDENMAsGA1UEAwwEVGVzdDAeFw0xNjA3MDcxMjE2MDBaFw0z
  NjA3MDIxMjE2MDBaMFgxCzAJBgNVBAYTAkdCMQ0wCwYDVQQIDARUZXN0MQ0wCwYD
  VQQHDARUZXN0MQ0wCwYDVQQKDARUZXN0MQ0wCwYDVQQLDARUZXN0MQ0wCwYDVQQD
  DARUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3uRyzTaYMWj/
  aGjqQtCMf4VMLIcR4o+yJVUp7CvhHIa/Ykx32OZMLth6DihykYzOFZj9wzD2a+GB
  8P3RkDMP5dxQF9yQSTTl/Ec7ZkHHnJzpao9mGsfJ7h24F4XTKC7QovaNw5HV83ej
  Vwrose8BHe5UlEpncTIqOY3JJbzzkrzSMzS7cGB1l55zXpDQVcRzv/182qFX2L3+
  ukIlbt3PNAjGPgKWYeVameTL38oKjJ5ftrADWjAWc7IBPw65KvqOTj5Jw+Jhkj4H
  4kkXKKn8N6ItiWclpWuKi8Va36VVUXnqPxOWnIK4AGnO8WEArRhU7XK+EiFK8TuH
  SSrOh9myWQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBvuGuwGrMSHNOKrWrWnwKD
  T3Ge9FfUonBmkzvGmWHfLROju3mwxAP0lB10+sn1gnjUHzKiVjeY8fuAjFQMrKUp
  HUWCaVPjsExd2OYu+6f+06rTrP98BNopuYWeIIkmc3JoFwOmSKTA5JIlNBDsN5F/
  PFcXE9Xjc4Ob1ut/bv6hJ1nbgbaVSNB4Zc+3oxi2X+xBut8zqATq7JYvO0SVH6h1
  oSp3lveosF9AQB8uLtWZFf3wnburr2zG6UhkSwQdy0GYEwTtqaYs7Ue7bHvO0GYG
  zPCVixoo4QoTiwDV7HGodrjvcMgtUgoDOhR6daZPEYV6rQJJoGhMF5+UAgS2KiMh
  -----END CERTIFICATE-----
tls-key: |
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEA3uRyzTaYMWj/aGjqQtCMf4VMLIcR4o+yJVUp7CvhHIa/Ykx3
  2OZMLth6DihykYzOFZj9wzD2a+GB8P3RkDMP5dxQF9yQSTTl/Ec7ZkHHnJzpao9m
  GsfJ7h24F4XTKC7QovaNw5HV83ejVwrose8BHe5UlEpncTIqOY3JJbzzkrzSMzS7
  cGB1l55zXpDQVcRzv/182qFX2L3+ukIlbt3PNAjGPgKWYeVameTL38oKjJ5ftrAD
  WjAWc7IBPw65KvqOTj5Jw+Jhkj4H4kkXKKn8N6ItiWclpWuKi8Va36VVUXnqPxOW
  nIK4AGnO8WEArRhU7XK+EiFK8TuHSSrOh9myWQIDAQABAoIBAGP7qhuvv7l6Vgep
  +FucXUneq3rV5AnzV4AzoaiVTleTgko/7wrW05m39ZhgQHRV6yP5CuwCDKf78mP+
  F4FNxnXfy/XINNkB56Cw+041d6sjH/ly9eRRdp1fq3KxzzSZO3G+k30E8CpUomqr
  NBKNGb0pabtTXO+EBzjmBzLsfX52anGEi2U2I/Q2srU+3FAkhjb9s9ZSgWh9zgrS
  0sK/oO04dlTLV0weq2oTHCX/ygQZpXvRXNJJVDRtst3R9EfUKr4YLWEK2k1PgWC+
  52CJoYETbQPGiJbzReTgYTlZYHSZfuso20sPfOc01qgcJIk5qOAS2dgU5EanSQEM
  0/HJ02ECgYEA+lHafm4psqi6YWLV0Evr54kzUVYXaBY/8Qbf4psCZ0o9VjfwzIPG
  ncgGXhyv9qlnFx38YEKAvn/HV52J8Qi5I8k4TBtYB/GYcNvpcNgR6uMcg+nS+0nf
  Y0BJgyUwY7Exh2BTIkJKLzIoOK0RKe1pk99Iboee9MDv6YaHQqlXaGUCgYEA4/ND
  3jb0PTEDrCtDTYOhNqcW/ER6rq8vSwR7uiHGBY6OiYcFgmV/AC3SUpVQurw5YIxh
  kQ1s7ncdBNN6fOpUEFYmBhPAkoHbVIcg98ZnzqM3tQU9o4sujT9pd8ATthAlqaBR
  G+5s7Cil9RtggCBXL1G+CQPS2TJoE8Tr/SfnEOUCgYA4Dx7Ek71I4pqi9rR1qpsR
  Rlu0yngBeoIlY2m+YQKfyTOFXI/T7WsMqOAsMXaC4htRRQjhMeONRiaJi6F51n9H
  8WdnO/RyCvwdwlI8UFdq6CPZswLp/fhGTP5pnWmB2gwCimLz2C6u9Sem0bN3VVEA
  qc+Z2UuS+qaAAP3Hww7tNQKBgQDO6gXEEzwWw4Qi5057cS2Ib5m0ufBm2oxiWxp4
  danLZ4DJI7ADkl/66J0O64zRRIQMuMDjqz0jJSpJNDHua8KM5bY0M//MvWU7UEHD
  x+x4rL2naq9t4awK+PGiis8Zp4SYefbGFOH4aFlkqUoqY7DgOiH3Cup8z32b3Fee
  f3cGZQKBgQDvsz2cBGNFW+U03sDeHqBbdim6E2RRvPrxLkeljSiU9RzJ3P76Ousv
  ORfedwfVln37uivduCeyBLMhaYWiW6CN4Di/d8LsI1hwe1MlNHuV2EptaFDzfjx8
  FWQQKAkL5KolhJye0Kz/X8CT3UMmhOK73UkUaOvMvdSjxLFgIruxWQ==
  -----END RSA PRIVATE KEY-----
resource-path: /resources
http-proxy: http://proxy.example.com:3128
no-proxy: localhost,.example.com
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
	config.RegisterIDP("usso", testIdentityProvider)
	config.RegisterIDP("keystone", testIdentityProvider)
	conf, err := s.readConfig(c, testConfig)
	c.Assert(err, gc.IsNil)
	// Check that the TLS configuration creates a valid *tls.Config
	tlsConfig := conf.TLSConfig()
	c.Assert(tlsConfig, gc.Not(gc.IsNil))
	conf.TLSCert = ""
	conf.TLSKey = ""

	var key bakery.KeyPair
	err = key.Public.UnmarshalText([]byte("CIdWcEUN+0OZnKW9KwruRQnQDY/qqzVdD30CijwiWCk="))
	c.Assert(err, gc.IsNil)
	err = key.Private.UnmarshalText([]byte("8PjzjakvIlh3BVFKe8axinRDutF6EDIfjtuf4+JaNow="))
	c.Assert(err, gc.IsNil)

	var adminPubKey bakery.PublicKey
	err = adminPubKey.UnmarshalText([]byte("dUnC8p9p3nygtE2h92a47Ooq0rXg0fVSm3YBWou5/UQ="))
	c.Assert(err, gc.IsNil)

	c.Assert(conf, jc.DeepEquals, &config.Config{
		MongoAddr:           "localhost:23456",
		APIAddr:             "1.2.3.4:5678",
		AuthUsername:        "myuser",
		AuthPassword:        "mypasswd",
		PrivateKey:          &key.Private,
		PublicKey:           &key.Public,
		AdminAgentPublicKey: &adminPubKey,
		Location:            "http://foo.com:1234",
		MaxMgoSessions:      10,
		WaitTimeout:         config.DurationString{Duration: time.Minute},
		IdentityProviders: []config.IdentityProvider{{
			IdentityProvider: IdentityProvider{
				Params: map[string]string{
					"type": "usso",
				},
			},
		}, {
			IdentityProvider: IdentityProvider{
				Params: map[string]string{
					"type": "keystone",
					"name": "ks1",
					"url":  "http://example.com/keystone",
				},
			},
		}},
		PrivateAddr:  "localhost",
		DebugTeams:   []string{"yellow", "cloud-green"},
		ResourcePath: "/resources",
		HTTPProxy:    "http://proxy.example.com:3128",
		NoProxy:      "localhost,.example.com",
	})
}

func (s *configSuite) TestReadErrorNotFound(c *gc.C) {
	cfg, err := config.Read(path.Join(c.MkDir(), "no-such-file.yaml"))
	c.Assert(err, gc.ErrorMatches, ".* no such file or directory")
	c.Assert(cfg, gc.IsNil)
}

func (s *configSuite) TestReadErrorEmpty(c *gc.C) {
	cfg, err := s.readConfig(c, "")
	c.Assert(err, gc.ErrorMatches, "missing fields mongo-addr, api-addr, auth-username, auth-password, private-key, public-key, location, max-mgo-sessions, private-addr in config file")
	c.Assert(cfg, gc.IsNil)
}

func (s *configSuite) TestReadErrorInvalidYAML(c *gc.C) {
	cfg, err := s.readConfig(c, ":")
	c.Assert(err, gc.ErrorMatches, "cannot parse .*: yaml: did not find expected key")
	c.Assert(cfg, gc.IsNil)
}

func (s *configSuite) TestUnrecognisedIDP(c *gc.C) {
	cfg, err := s.readConfig(c, `
identity-providers:
 - type: nosuch
`)
	c.Assert(err, gc.ErrorMatches, `cannot parse ".*": unrecognised identity provider type "nosuch"`)
	c.Assert(cfg, gc.IsNil)
}

type IdentityProvider struct {
	idp.IdentityProvider
	Params map[string]string
}

func testIdentityProvider(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
	idp := IdentityProvider{
		IdentityProvider: nil,
		Params:           make(map[string]string),
	}
	if err := unmarshal(&idp.Params); err != nil {
		return nil, err
	}
	return idp, nil
}
