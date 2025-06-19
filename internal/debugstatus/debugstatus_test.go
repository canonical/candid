package debugstatus_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	jujutesting "github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"

	"github.com/juju/mgo/v2"
	"github.com/juju/testing/httptesting"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"

	"github.com/canonical/candid/internal/debugstatus"
)

type statusSuite struct {
	jujutesting.IsolationSuite
}

var _ = gc.Suite(&statusSuite{})

func makeCheckerFunc(key, name, value string, passed bool) debugstatus.CheckerFunc {
	return func(context.Context) (string, debugstatus.CheckResult) {
		time.Sleep(time.Microsecond)
		return key, debugstatus.CheckResult{
			Name:   name,
			Value:  value,
			Passed: passed,
		}
	}
}

func (s *statusSuite) TestCheck(c *gc.C) {
	results := debugstatus.Check(
		context.Background(),
		makeCheckerFunc("check1", "check1 name", "value1", true),
		makeCheckerFunc("check2", "check2 name", "value2", false),
		makeCheckerFunc("check3", "check3 name", "value3", true),
	)
	for key, r := range results {
		if r.Duration < time.Microsecond {
			c.Errorf("got %v want >1µs", r.Duration)
		}
		r.Duration = 0
		results[key] = r
	}

	c.Assert(results, jc.DeepEquals, map[string]debugstatus.CheckResult{
		"check1": {
			Name:   "check1 name",
			Value:  "value1",
			Passed: true,
		},
		"check2": {
			Name:   "check2 name",
			Value:  "value2",
			Passed: false,
		},
		"check3": {
			Name:   "check3 name",
			Value:  "value3",
			Passed: true,
		},
	})
}

func (s *statusSuite) TestServerStartTime(c *gc.C) {
	startTime := time.Now()
	s.PatchValue(&debugstatus.StartTime, startTime)
	key, result := debugstatus.ServerStartTime(context.Background())
	c.Assert(key, gc.Equals, "server_started")
	c.Assert(result, jc.DeepEquals, debugstatus.CheckResult{
		Name:   "Server started",
		Value:  startTime.String(),
		Passed: true,
	})
}

// pinger implements a debugstatus.Pinger used for tests.
type pinger struct {
	err error
}

func (p pinger) Ping() error {
	return p.err
}

var mongoCollectionsTests = []struct {
	about        string
	collector    collector
	expectValue  string
	expectPassed bool
}{{
	about: "all collection exist",
	collector: collector{
		expected: []string{"coll1", "coll2"},
		obtained: []string{"coll1", "coll2"},
	},
	expectValue:  "All required collections exist",
	expectPassed: true,
}, {
	about:        "no collections",
	expectValue:  "All required collections exist",
	expectPassed: true,
}, {
	about: "missing collections",
	collector: collector{
		expected: []string{"coll1", "coll2", "coll3"},
		obtained: []string{"coll2"},
	},
	expectValue: "Missing collections: [coll1 coll3]",
}, {
	about: "error retrieving collections",
	collector: collector{
		err: errors.New("bad wolf"),
	},
	expectValue: "Cannot get collections: bad wolf",
}}

func (s *statusSuite) TestMongoCollections(c *gc.C) {
	for i, test := range mongoCollectionsTests {
		c.Logf("test %d: %s", i, test.about)

		// Ensure a connection established is properly reported.
		check := debugstatus.MongoCollections(test.collector)
		key, result := check(context.Background())
		c.Assert(key, gc.Equals, "mongo_collections")
		c.Assert(result, jc.DeepEquals, debugstatus.CheckResult{
			Name:   "MongoDB collections",
			Value:  test.expectValue,
			Passed: test.expectPassed,
		})
	}
}

// collector implements a debugstatus.Collector used for tests.
type collector struct {
	expected []string
	obtained []string
	err      error
}

func (c collector) CollectionNames() ([]string, error) {
	return c.obtained, c.err
}

func (c collector) Collections() []*mgo.Collection {
	collections := make([]*mgo.Collection, len(c.expected))
	for i, name := range c.expected {
		collections[i] = &mgo.Collection{Name: name}
	}
	return collections
}

var renameTests = []struct {
	about string
	key   string
	name  string
}{{
	about: "rename key",
	key:   "new-key",
}, {
	about: "rename name",
	name:  "new name",
}, {
	about: "rename both",
	key:   "another-key",
	name:  "another name",
}, {
	about: "do not rename",
}}

var reqServer = httprequest.Server{
	ErrorMapper: func(ctx context.Context, err error) (httpStatus int, errorBody interface{}) {
		return http.StatusInternalServerError, httprequest.RemoteError{
			Message: err.Error(),
		}
	},
}

type handlerSuite struct {
}

var _ = gc.Suite(&handlerSuite{})

var errUnauthorized = errgo.New("you shall not pass!")

func newHTTPHandler(h *debugstatus.Handler) http.Handler {
	errMapper := func(ctx context.Context, err error) (httpStatus int, errorBody interface{}) {
		code, status := "", http.StatusInternalServerError
		switch errgo.Cause(err) {
		case errUnauthorized:
			code, status = "unauthorized", http.StatusUnauthorized
		case debugstatus.ErrNoPprofConfigured:
			code, status = "forbidden", http.StatusForbidden
		case debugstatus.ErrNoTraceConfigured:
			code, status = "forbidden", http.StatusForbidden
		}
		return status, httprequest.RemoteError{
			Code:    code,
			Message: err.Error(),
		}
	}
	srv := httprequest.Server{
		ErrorMapper: errMapper,
	}

	handlers := srv.Handlers(func(p httprequest.Params) (*debugstatus.Handler, context.Context, error) {
		return h, p.Context, nil
	})
	r := httprouter.New()
	for _, h := range handlers {
		r.Handle(h.Method, h.Path, h.Handle)
	}
	return r
}

func (s *handlerSuite) TestServeDebugStatus(c *gc.C) {
	httpHandler := newHTTPHandler(&debugstatus.Handler{
		Check: func(ctx context.Context) map[string]debugstatus.CheckResult {
			return debugstatus.Check(ctx, debugstatus.ServerStartTime)
		},
	})
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler: httpHandler,
		URL:     "/debug/status",
		ExpectBody: httptesting.BodyAsserter(func(c *gc.C, body json.RawMessage) {
			var result map[string]debugstatus.CheckResult
			err := json.Unmarshal(body, &result)
			c.Assert(err, gc.IsNil)
			for k, v := range result {
				v.Duration = 0
				result[k] = v
			}
			c.Assert(result, jc.DeepEquals, map[string]debugstatus.CheckResult{
				"server_started": {
					Name:   "Server started",
					Value:  debugstatus.StartTime.String(),
					Passed: true,
				},
			})
		}),
	})
}

func (s *handlerSuite) TestServeDebugStatusWithNilCheck(c *gc.C) {
	httpHandler := newHTTPHandler(&debugstatus.Handler{})
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:    httpHandler,
		URL:        "/debug/status",
		ExpectBody: map[string]debugstatus.CheckResult{},
	})
}

func (s *handlerSuite) TestServeDebugInfo(c *gc.C) {
	version := debugstatus.Version{
		GitCommit: "some-git-status",
		Version:   "a-version",
	}
	httpHandler := newHTTPHandler(&debugstatus.Handler{
		Version: version,
	})
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      httpHandler,
		URL:          "/debug/info",
		ExpectStatus: http.StatusOK,
		ExpectBody:   version,
	})
}

var debugPprofPaths = []string{
	"/debug/pprof/",
	"/debug/pprof/cmdline",
	"/debug/pprof/profile?seconds=1",
	"/debug/pprof/symbol",
	"/debug/pprof/goroutine",
}

func (s *handlerSuite) TestServeDebugPprof(c *gc.C) {
	httpHandler := newHTTPHandler(&debugstatus.Handler{
		CheckPprofAllowed: func(req *http.Request) error {
			if req.Header.Get("Authorization") == "" {
				return errUnauthorized
			}
			return nil
		},
	})
	authHeader := make(http.Header)
	authHeader.Set("Authorization", "let me in")
	for i, path := range debugPprofPaths {
		c.Logf("%d. %s", i, path)
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler:      httpHandler,
			URL:          path,
			ExpectStatus: http.StatusUnauthorized,
			ExpectBody: httprequest.RemoteError{
				Code:    "unauthorized",
				Message: "you shall not pass!",
			},
		})
		rr := httptesting.DoRequest(c, httptesting.DoRequestParams{
			Handler: httpHandler,
			URL:     path,
			Header:  authHeader,
		})
		c.Assert(rr.Code, gc.Equals, http.StatusOK)
	}
}

func (s *handlerSuite) TestDebugPprofForbiddenWhenNotConfigured(c *gc.C) {
	httpHandler := newHTTPHandler(&debugstatus.Handler{})
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      httpHandler,
		URL:          "/debug/pprof/",
		ExpectStatus: http.StatusForbidden,
		ExpectBody: httprequest.RemoteError{
			Code:    "forbidden",
			Message: "no pprof access configured",
		},
	})
}

var debugTracePaths = []string{
	"/debug/events",
	"/debug/requests",
}

func (s *handlerSuite) TestServeTraceEvents(c *gc.C) {
	httpHandler := newHTTPHandler(&debugstatus.Handler{
		CheckTraceAllowed: func(req *http.Request) (bool, error) {
			if req.Header.Get("Authorization") == "" {
				return false, errUnauthorized
			}
			return false, nil
		},
	})
	authHeader := make(http.Header)
	authHeader.Set("Authorization", "let me in")
	for i, path := range debugTracePaths {
		c.Logf("%d. %s", i, path)
		httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
			Handler:      httpHandler,
			URL:          path,
			ExpectStatus: http.StatusUnauthorized,
			ExpectBody: httprequest.RemoteError{
				Code:    "unauthorized",
				Message: "you shall not pass!",
			},
		})
		rr := httptesting.DoRequest(c, httptesting.DoRequestParams{
			Handler: httpHandler,
			URL:     path,
			Header:  authHeader,
		})
		c.Assert(rr.Code, gc.Equals, http.StatusOK)
	}
}

func (s *handlerSuite) TestDebugEventsForbiddenWhenNotConfigured(c *gc.C) {
	httpHandler := newHTTPHandler(&debugstatus.Handler{})
	httptesting.AssertJSONCall(c, httptesting.JSONCallParams{
		Handler:      httpHandler,
		URL:          "/debug/events",
		ExpectStatus: http.StatusForbidden,
		ExpectBody: httprequest.RemoteError{
			Code:    "forbidden",
			Message: "no trace access configured",
		},
	})
}
