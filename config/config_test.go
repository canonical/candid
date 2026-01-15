// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package config_test

import (
	"os"
	"path"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"

	"github.com/canonical/candid/config"
	"github.com/canonical/candid/idp"
	"github.com/canonical/candid/store"
	_ "github.com/canonical/candid/store/memstore"
)

const testConfig = `
listen-address: 1.2.3.4:5678
foo: 1
bar: false
admin-password: mypasswd
private-key: 8PjzjakvIlh3BVFKe8axinRDutF6EDIfjtuf4+JaNow=
public-key: CIdWcEUN+0OZnKW9KwruRQnQDY/qqzVdD30CijwiWCk=
admin-agent-public-key: dUnC8p9p3nygtE2h92a47Ooq0rXg0fVSm3YBWou5/UQ=
location: http://foo.com:1234
storage:
  type: test
  attribute: hello
rendezvous-timeout: 1m
identity-providers:
 - type: usso
 - type: keystone
   name: ks1
   url: http://example.com/keystone
private-addr: localhost
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
HSTS-max-age: 31536000
HSTS-include-subdomains: true
TLS-cipher-suites:
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
resource-path: /resources
http-proxy: http://proxy.example.com:3128
no-proxy: localhost,.example.com
redirect-login-trusted-urls:
- https://example.com/1
- https://example.com/2
redirect-login-trusted-domains:
- www.example.com
- "*.example.net"
api-macaroon-timeout: 2h
discharge-macaroon-timeout: 24h
discharge-token-timeout: 6h
enable-email-login: true
`

const testConfigWithUnsupportedCipher = `
listen-address: 1.2.3.4:5678
foo: 1
bar: false
admin-password: mypasswd
private-key: 8PjzjakvIlh3BVFKe8axinRDutF6EDIfjtuf4+JaNow=
public-key: CIdWcEUN+0OZnKW9KwruRQnQDY/qqzVdD30CijwiWCk=
admin-agent-public-key: dUnC8p9p3nygtE2h92a47Ooq0rXg0fVSm3YBWou5/UQ=
location: http://foo.com:1234
storage:
  type: test
  attribute: hello
rendezvous-timeout: 1m
identity-providers:
 - type: usso
 - type: keystone
   name: ks1
   url: http://example.com/keystone
private-addr: localhost
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
HSTS-max-age: 31536000
HSTS-include-subdomains: true
TLS-cipher-suites:
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- WRONG_CIPHER_SUITE
resource-path: /resources
http-proxy: http://proxy.example.com:3128
no-proxy: localhost,.example.com
redirect-login-trusted-urls:
- https://example.com/1
- https://example.com/2
redirect-login-trusted-domains:
- www.example.com
- "*.example.net"
api-macaroon-timeout: 2h
discharge-macaroon-timeout: 24h
discharge-token-timeout: 6h
enable-email-login: true
`

func readConfig(c *qt.C, content string) (*config.Config, error) {
	// Write the configuration content to file.
	path := path.Join(c.TempDir(), "config.yaml")
	err := os.WriteFile(path, []byte(content), 0666)
	c.Assert(err, qt.IsNil)

	// Read the configuration.
	return config.Read(path)
}

func TestRead(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	idp.Register("usso", testIdentityProvider)
	idp.Register("keystone", testIdentityProvider)
	store.Register("test", testStorageBackend)

	// check if wrong cipher suite names are detected
	conf, err := readConfig(c, testConfigWithUnsupportedCipher)
	tlsConfig := conf.TLSConfig()
	c.Assert(tlsConfig, qt.IsNil)

	// continue with valid config
	conf, err = readConfig(c, testConfig)
	c.Assert(err, qt.IsNil)
	// Check that the TLS configuration creates a valid *tls.Config
	tlsConfig = conf.TLSConfig()
	c.Assert(tlsConfig, qt.Not(qt.IsNil))
	conf.TLSCert = ""
	conf.TLSKey = ""

	var key bakery.KeyPair
	err = key.Public.UnmarshalText([]byte("CIdWcEUN+0OZnKW9KwruRQnQDY/qqzVdD30CijwiWCk="))
	c.Assert(err, qt.IsNil)
	err = key.Private.UnmarshalText([]byte("8PjzjakvIlh3BVFKe8axinRDutF6EDIfjtuf4+JaNow="))
	c.Assert(err, qt.IsNil)

	var adminPubKey bakery.PublicKey
	err = adminPubKey.UnmarshalText([]byte("dUnC8p9p3nygtE2h92a47Ooq0rXg0fVSm3YBWou5/UQ="))
	c.Assert(err, qt.IsNil)

	c.Assert(conf, qt.DeepEquals, &config.Config{
		Storage: &store.Config{
			BackendFactory: storageBackend{
				Params: map[string]string{
					"type":      "test",
					"attribute": "hello",
				},
			},
		},
		IdentityProviders: []idp.Config{{
			IdentityProvider: identityProvider{
				Params: map[string]string{
					"type": "usso",
				},
			},
		}, {
			IdentityProvider: identityProvider{
				Params: map[string]string{
					"type": "keystone",
					"name": "ks1",
					"url":  "http://example.com/keystone",
				},
			},
		}},
		ListenAddress:         "1.2.3.4:5678",
		AdminPassword:         "mypasswd",
		PrivateKey:            &key.Private,
		PublicKey:             &key.Public,
		AdminAgentPublicKey:   &adminPubKey,
		Location:              "http://foo.com:1234",
		RendezvousTimeout:     config.DurationString{Duration: time.Minute},
		HSTSMaxAge:            31536000,
		HSTSIncludeSubdomains: true,
		TLSCipherSuites: []string{
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		},
		PrivateAddr:  "localhost",
		ResourcePath: "/resources",
		HTTPProxy:    "http://proxy.example.com:3128",
		NoProxy:      "localhost,.example.com",
		RedirectLoginTrustedURLs: []string{
			"https://example.com/1",
			"https://example.com/2",
		},
		RedirectLoginTrustedDomains: []string{
			"www.example.com",
			"*.example.net",
		},
		APIMacaroonTimeout:       config.DurationString{Duration: 2 * time.Hour},
		DischargeMacaroonTimeout: config.DurationString{Duration: 24 * time.Hour},
		DischargeTokenTimeout:    config.DurationString{Duration: 6 * time.Hour},
		EnableEmailLogin:         true,
	})
}

func TestReadErrorNotFound(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	cfg, err := config.Read(path.Join(c.TempDir(), "no-such-file.yaml"))
	c.Assert(err, qt.ErrorMatches, ".* no such file or directory")
	c.Assert(cfg, qt.IsNil)
}

func TestReadErrorEmpty(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	cfg, err := readConfig(c, "")
	c.Assert(err, qt.ErrorMatches, "missing fields storage, listen-address, private-key, public-key, location, private-addr in config file")
	c.Assert(cfg, qt.IsNil)
}

func TestReadErrorInvalidYAML(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	cfg, err := readConfig(c, ":")
	c.Assert(err, qt.ErrorMatches, "cannot parse .*: yaml: did not find expected key")
	c.Assert(cfg, qt.IsNil)
}

func TestUnrecognisedIDP(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	cfg, err := readConfig(c, `
identity-providers:
 - type: nosuch
`)
	c.Assert(err, qt.ErrorMatches, `cannot parse ".*": unrecognised identity provider type "nosuch"`)
	c.Assert(cfg, qt.IsNil)
}

type identityProvider struct {
	idp.IdentityProvider
	Params map[string]string
}

func testIdentityProvider(unmarshal func(interface{}) error) (idp.IdentityProvider, error) {
	idp := identityProvider{
		Params: make(map[string]string),
	}
	if err := unmarshal(&idp.Params); err != nil {
		return nil, err
	}
	return idp, nil
}

type storageBackend struct {
	store.BackendFactory
	Params map[string]string
}

func testStorageBackend(unmarshal func(interface{}) error) (store.BackendFactory, error) {
	backend := storageBackend{
		Params: make(map[string]string),
	}
	if err := unmarshal(&backend.Params); err != nil {
		return nil, err
	}
	return backend, nil
}
