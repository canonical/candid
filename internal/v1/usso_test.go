// Copyright 2014 Canonical Ltd.

package v1

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
)

type ussoSuite struct {
	testing.LoggingCleanupSuite
}

var _ = gc.Suite(&ussoSuite{})

// TODO this only tests a small part of the openid logic in order to test some specific parts
// of identity. An expanded test suite that can do end-to-end testing of openid is required.

var verifyCallbackTests = []struct {
	about      string
	location   string
	path       string
	fields     map[string]string
	expectInfo *verifiedUserInfo
	expectErr  string
}{{
	about:    "good callback - no extensions",
	location: "https://api.jujucharms.com/identity",
	path:     "/v1/idp/usso/callback?waitid=1",
	fields: map[string]string{
		"mode":        "id_res",
		"op_endpoint": "https://login.example.com/",
		"claimed_id":  "https://example.com/+id/AAAAAAA",
		"identity":    "https://example.com/+id/AAAAAAA",
		"return_to":   "https://api.jujucharms.com/identity/v1/idp/usso/callback?waitid=1",
	},
	expectInfo: &verifiedUserInfo{
		User: "https://example.com/+id/AAAAAAA",
	},
}, {
	about:    "good callback - all extensions",
	location: "https://api.jujucharms.com/identity",
	path:     "/v1/idp/usso/callback?waitid=1",
	fields: map[string]string{
		"mode":          "id_res",
		"op_endpoint":   "https://login.example.com/",
		"claimed_id":    "https://example.com/+id/AAAAAAA",
		"identity":      "https://example.com/+id/AAAAAAA",
		"return_to":     "https://api.jujucharms.com/identity/v1/idp/usso/callback?waitid=1",
		"ns.sreg":       "http://openid.net/extensions/sreg/1.1",
		"sreg.nickname": "test",
		"sreg.fullname": "Test User",
		"sreg.email":    "test@example.com",
		"ns.lp":         "http://ns.launchpad.net/2007/openid-teams",
		"lp.is_member":  "test,test2",
	},
	expectInfo: &verifiedUserInfo{
		User:     "https://example.com/+id/AAAAAAA",
		Nickname: "test",
		FullName: "Test User",
		Email:    "test@example.com",
		Groups:   []string{"test", "test2"},
	},
}, {
	about:    "bad return_to",
	location: "https://api.jujucharms.com/identity",
	path:     "/v1/idp/usso/callback?waitid=1",
	fields: map[string]string{
		"mode":        "id_res",
		"op_endpoint": "https://login.example.com/",
		"claimed_id":  "https://example.com/+id/AAAAAAA",
		"identity":    "https://example.com/+id/AAAAAAA",
		"return_to":   "https://api.jujucharms.com/charmstore/v1/idp/usso/callback?waitid=1",
	},
	expectErr: "openID verification failed: Scheme, host or path don't match in return_to URL",
}}

func (s *ussoSuite) TestVerifyCallback(c *gc.C) {
	s.PatchValue(&http.DefaultTransport, testOpenID{c})

	for i, test := range verifyCallbackTests {
		c.Logf("test %d: %s", i, test.about)
		p := newUSSOProvider(test.location)
		fields := test.fields
		// Create a valid positive assertion, see http://openid.net/specs/openid-authentication-2_0.html#positive_assertions for details.
		fields["assoc_id"] = "0"
		// Create a valid nonce with the current time.
		fields["response_nonce"] = fmt.Sprintf("%s%d", time.Now().UTC().Format(time.RFC3339), i)
		// Create a valid signature for the response.
		mac := hmac.New(sha1.New, []byte{0})
		signed := make([]string, 0, len(fields))
		for k, v := range fields {
			if strings.HasPrefix(k, "ns.") {
				continue
			}
			signed = append(signed, k)
			writeKeyValue(mac, k, v)
		}
		fields["signed"] = strings.Join(signed, ",")
		fields["sig"] = base64.URLEncoding.EncodeToString(mac.Sum(nil))
		// Encode the response as an inderect communication, see http://openid.net/specs/openid-authentication-2_0.html#indirect_comm for details.
		u, err := url.Parse(test.path)
		vals, err := url.ParseQuery(u.RawQuery)
		c.Assert(err, gc.IsNil)
		vals.Set("openid.ns", "http://specs.openid.net/auth/2.0")
		for k, v := range fields {
			vals.Set("openid."+k, v)
		}
		u.RawQuery = vals.Encode()
		requestURI := u.String()
		u.Scheme = "http"
		u.Host = "example.com"
		info, err := p.verifyCallback(nil, &http.Request{
			URL:        u,
			RequestURI: requestURI,
		})
		if test.expectErr != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErr)
			continue
		}
		c.Assert(err, gc.IsNil)
		c.Assert(info, jc.DeepEquals, test.expectInfo)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func writeKeyValue(w io.Writer, k, v string) error {
	_, err := fmt.Fprintf(w, "%s:%s\n", k, v)
	return err
}

type testOpenID struct {
	c *gc.C
}

func (t testOpenID) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	t.c.Logf("%s %s %s", req.Method, req.URL, req.Proto)
	if req.URL.Host == "login.example.com" && req.Method == "POST" {
		_, err := w.Write([]byte("ns:http://specs.openid.net/auth/2.0\nis_valid:true\n"))
		if err != nil {
			panic(err)
		}
		return
	} else if req.URL.Host == "example.com" && (req.Method == "GET" || req.Method == "HEAD") {
		w.Header().Set("Content-Type", "application/xrds+xml")
		_, err := w.Write([]byte(
			`<?xml version="1.0"?>
<xrds:XRDS xmlns="xri://$xrd*($v*2.0)" xmlns:xrds="xri://$xrds">
	<XRD>
		<Service priority="0">
			<Type>http://specs.openid.net/auth/2.0/signon</Type>
			<URI>https://login.example.com/</URI>
		</Service>
	</XRD>
</xrds:XRDS>
`))
		if err != nil {
			panic(err)
		}
		return
	}
	w.WriteHeader(http.StatusNotFound)
	return
}

func (t testOpenID) RoundTrip(req *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t.ServeHTTP(w, req)
	if req.Body != nil {
		io.Copy(ioutil.Discard, req.Body)
		req.Body.Close()
		req.Body = nil
	}
	return &http.Response{
		StatusCode:    w.Code,
		Header:        w.HeaderMap,
		Body:          ioutil.NopCloser(w.Body),
		ContentLength: int64(w.Body.Len()),
		Request:       req,
	}, nil
}
