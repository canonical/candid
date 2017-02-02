// Copyright 2014 Canonical Ltd.

package store_test

import (
	"bufio"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/juju/idmclient/params"
	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/prometheus/client_golang/prometheus"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2/bson"
	"launchpad.net/lpad"

	"github.com/CanonicalLtd/blues-identity/internal/mongodoc"
	"github.com/CanonicalLtd/blues-identity/internal/store"
)

type storeSuite struct {
	testing.IsolatedMgoSuite
	pool *store.Pool
}

var _ = gc.Suite(&storeSuite{})

func (s *storeSuite) SetUpTest(c *gc.C) {
	s.IsolatedMgoSuite.SetUpTest(c)
	var err error
	s.pool, err = store.NewPool(s.Session.Copy().DB("store-tests"), store.StoreParams{
		MaxMgoSessions: 10,
		PrivateAddr:    "localhost",
	})
	c.Assert(err, gc.IsNil)
}

func (s *storeSuite) TearDownTest(c *gc.C) {
	s.pool.Close()
	s.IsolatedMgoSuite.TearDownTest(c)
}

func (s *storeSuite) TestNew(c *gc.C) {
	db := s.Session.DB("store-tests")

	// Add an identity to the identities collection using mgo directly.
	err := db.C("identities").Insert(&mongodoc.Identity{
		Username:   "who",
		ExternalID: "http://example.com/who",
		Email:      "who@example.com",
		FullName:   "Who Am I",
		Groups: []string{
			"group1",
		},
	})
	c.Assert(err, gc.IsNil)

	// Set up a new store.
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)

	// Retrieve the identity using the store object.
	var doc mongodoc.Identity
	err = store.DB.Identities().Find(bson.D{{"username", "who"}}).One(&doc)
	c.Assert(err, gc.IsNil)
	c.Assert(doc.Username, gc.Equals, "who")
	c.Assert(doc.ExternalID, gc.Equals, "http://example.com/who")
	c.Assert(doc.Email, gc.Equals, "who@example.com")
	c.Assert(doc.FullName, gc.Equals, "Who Am I")
	c.Assert(doc.Groups, gc.DeepEquals, []string{"group1"})
}

var upsertUserTests = []struct {
	about     string
	identity  *mongodoc.Identity
	expectErr string
}{{
	about: "insert user",
	identity: &mongodoc.Identity{
		Username:   "test",
		ExternalID: "http://example.com/test",
		Email:      "test@example.com",
		FullName:   "Test User",
		Groups: []string{
			"test",
		},
		SSHKeys: []string{
			"ssh-key-1",
		},
		ExtraInfo: map[string][]byte{
			"extra-info-1": []byte("null"),
		},
	},
}, {
	about: "clashing username",
	identity: &mongodoc.Identity{
		Username:   "existing",
		ExternalID: "http://example.com/test-clashing",
		Email:      "existing@example.com",
		FullName:   "Existing User",
		Groups: []string{
			"test",
		},
	},
	expectErr: "cannot add user: duplicate username or external_id",
}, {
	about: "clashing external ID",
	identity: &mongodoc.Identity{
		Username:   "test-clashing",
		ExternalID: "http://example.com/existing",
		Email:      "existing@example.com",
		FullName:   "Existing User",
		Groups: []string{
			"test",
		},
	},
	expectErr: "cannot add user: duplicate username or external_id",
}, {
	about: "not fully specified",
	identity: &mongodoc.Identity{
		Username:   "test",
		ExternalID: "",
		Email:      "test@example.com",
		FullName:   "Test User",
		Groups: []string{
			"test",
		},
	},
	expectErr: "no external_id specified",
}, {
	about: "invalid username",
	identity: &mongodoc.Identity{
		Username:   "test-",
		ExternalID: "http://example.com/test-",
		Email:      "test@example.com",
		FullName:   "Test User",
		Groups: []string{
			"test",
		},
	},
	expectErr: `invalid username "test-"`,
}, {
	about: "user with domain",
	identity: &mongodoc.Identity{
		Username:   "test2@example",
		ExternalID: "http://example.com/test2",
		Email:      "test2@example.com",
		FullName:   "Test User II",
		Groups: []string{
			"test",
		},
		SSHKeys: []string{
			"ssh-key-1",
		},
		ExtraInfo: map[string][]byte{
			"extra-info-1": []byte("null"),
		},
	},
}}

func (s *storeSuite) TestUpsertUser(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)

	// Add existing interactive user.
	err := store.UpsertUser(&mongodoc.Identity{
		Username:   "existing",
		ExternalID: "http://example.com/existing",
		Email:      "existing@example.com",
		FullName:   "Existing User",
		Groups: []string{
			"test",
		},
	})
	c.Assert(err, gc.IsNil)

	for i, test := range upsertUserTests {
		c.Logf("%d: %s", i, test.about)
		err := store.UpsertUser(test.identity)
		if test.expectErr != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErr)
			continue
		}
		c.Assert(err, gc.IsNil)
		var doc mongodoc.Identity
		err = store.DB.Identities().Find(bson.D{{"username", test.identity.Username}}).One(&doc)
		c.Assert(err, gc.IsNil)
		c.Assert(&doc, jc.DeepEquals, test.identity)
	}
}

var upsertAgentTests = []struct {
	about     string
	identity  *mongodoc.Identity
	expectErr string
}{{
	about: "insert agent",
	identity: &mongodoc.Identity{
		Username: "agent@owner",
		Groups: []string{
			"test",
		},
		Owner:      "owner",
		PublicKeys: []mongodoc.PublicKey{{Key: []byte("0000000000000000000000000000000")}},
	},
}, {
	about: "duplicate agent",
	identity: &mongodoc.Identity{
		Username: "existing-agent@owner",
		Groups: []string{
			"test",
		},
		Owner: "another-owner",
		PublicKeys: []mongodoc.PublicKey{
			{Key: []byte("0000000000000000000000000000000")},
			{Key: []byte("1111111111111111111111111111111")},
		},
	},
	expectErr: "already exists",
}, {
	about: "owner not  specified",
	identity: &mongodoc.Identity{
		Username: "agent@admin@idm",
		Groups: []string{
			"test",
		},
		Owner: "",
		PublicKeys: []mongodoc.PublicKey{
			{Key: []byte("0000000000000000000000000000000")},
			{Key: []byte("1111111111111111111111111111111")},
		},
	},
	expectErr: `invalid owner ""`,
}, {
	about: "invalid agent name - no owner part",
	identity: &mongodoc.Identity{
		Username: "agent",
		Groups: []string{
			"test",
		},
		Owner: "owner",
		PublicKeys: []mongodoc.PublicKey{
			{Key: []byte("0000000000000000000000000000000")},
			{Key: []byte("1111111111111111111111111111111")},
		},
	},
	expectErr: `invalid username "agent"`,
}, {
	about: "invalid agent name - invalid name part",
	identity: &mongodoc.Identity{
		Username: "agent-@owner",
		Groups: []string{
			"test",
		},
		Owner: "owner",
		PublicKeys: []mongodoc.PublicKey{
			{Key: []byte("0000000000000000000000000000000")},
			{Key: []byte("1111111111111111111111111111111")},
		},
	},
	expectErr: `invalid username "agent-@owner"`,
}, {
	about: "invalid agent name - invalid owner part",
	identity: &mongodoc.Identity{
		Username: "agent@owner@owner@owner",
		Groups: []string{
			"test",
		},
		Owner: "owner@owner@owner",
		PublicKeys: []mongodoc.PublicKey{
			{Key: []byte("0000000000000000000000000000000")},
			{Key: []byte("1111111111111111111111111111111")},
		},
	},
	expectErr: `invalid username "agent@owner@owner@owner"`,
}}

func (s *storeSuite) TestUpsertAgent(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)

	// Add existing agent user
	err := store.UpsertAgent(&mongodoc.Identity{
		Username: "existing-agent@owner",
		Groups: []string{
			"test",
		},
		Owner:      "owner",
		PublicKeys: []mongodoc.PublicKey{{Key: []byte("00000000000000000000000000000000")}},
	})
	c.Assert(err, gc.IsNil)

	for i, test := range upsertAgentTests {
		c.Logf("%d: %s", i, test.about)
		err := store.UpsertAgent(test.identity)
		if test.expectErr != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErr)
			continue
		}
		c.Assert(err, gc.IsNil)
		var doc mongodoc.Identity
		err = store.DB.Identities().Find(bson.D{{"username", test.identity.Username}}).One(&doc)
		c.Assert(err, gc.IsNil)
		c.Assert(&doc, jc.DeepEquals, test.identity)
	}
}

func (s *storeSuite) TestUpsertUserEmptyUserInformation(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	id := &mongodoc.Identity{
		Username:   "test",
		ExternalID: "http://example.com/test",
	}
	err := store.UpsertUser(id)
	c.Assert(err, gc.IsNil)
	var doc map[string]interface{}
	err = store.DB.Identities().Find(bson.D{{"username", "test"}}).One(&doc)
	c.Assert(err, gc.IsNil)
	_, ok := doc["_id"]
	c.Assert(ok, gc.Equals, true)
	delete(doc, "_id")
	c.Assert(doc, jc.DeepEquals, map[string]interface{}{
		"username":    "test",
		"external_id": "http://example.com/test",
		"email":       "",
		"gravatarid":  "",
		"fullname":    "",
	})
}

func (s *storeSuite) TestUpsertUserDedupeGroups(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)

	// Add interactive user.
	id := &mongodoc.Identity{
		Username:   "test",
		ExternalID: "http://example.com/test",
		Email:      "test@example.com",
		FullName:   "Test User",
		Groups: []string{
			"test",
			"test2",
			"test2",
		},
	}
	err := store.UpsertUser(id)
	c.Assert(err, gc.IsNil)

	expect := &mongodoc.Identity{
		Username:   "test",
		ExternalID: "http://example.com/test",
		Email:      "test@example.com",
		FullName:   "Test User",
		Groups: []string{
			"test",
			"test2",
		},
	}

	var doc mongodoc.Identity
	err = store.DB.Identities().Find(bson.D{{"username", "test"}}).One(&doc)
	c.Assert(err, gc.IsNil)
	c.Assert(&doc, jc.DeepEquals, expect)
}

var setGroupsTests = []struct {
	about     string
	identity  *mongodoc.Identity
	expectErr string
}{{
	about: "update interactive user",
	identity: &mongodoc.Identity{
		Username:   "existing",
		ExternalID: "http://example.com/existing",
		Email:      "existing@example.com",
		FullName:   "Existing User",
		Groups: []string{
			"test",
			"test2",
		},
	},
}, {
	about: "update existing agent",
	identity: &mongodoc.Identity{
		Username: "existing-agent@owner",
		Groups: []string{
			"test",
			"test2",
		},
		Owner: "owner",
		PublicKeys: []mongodoc.PublicKey{
			{Key: []byte("0000000000000000000000000000000")},
		},
	},
}, {
	about: "update a non existing agent",
	identity: &mongodoc.Identity{
		Username:   "non-existing-agent@owner",
		ExternalID: "",
		Email:      "existing@example.com",
		FullName:   "Existing User",
		Groups: []string{
			"test",
			"test2",
		},
		Owner: "owner",
		PublicKeys: []mongodoc.PublicKey{
			{Key: []byte("0000000000000000000000000000000")},
		},
	},
	expectErr: "user \"non-existing-agent@owner\" not found: not found",
}}

func (s *storeSuite) TestSetGroups(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)

	// Add existing interactive user.
	err := store.UpsertUser(&mongodoc.Identity{
		Username:   "existing",
		ExternalID: "http://example.com/existing",
		Email:      "existing@example.com",
		FullName:   "Existing User",
		Groups: []string{
			"test",
		},
	})
	c.Assert(err, gc.IsNil)

	// Add existing agent user
	err = store.UpsertAgent(&mongodoc.Identity{
		Username: "existing-agent@owner",
		Groups: []string{
			"test",
		},
		Owner:      "owner",
		PublicKeys: []mongodoc.PublicKey{{Key: []byte("0000000000000000000000000000000")}},
	})
	c.Assert(err, gc.IsNil)

	for i, test := range setGroupsTests {
		c.Logf("%d: %s", i, test.about)
		err := store.SetGroups(params.Username(test.identity.Username), test.identity.Groups)
		if test.expectErr != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErr)
			continue
		}
		c.Assert(err, gc.IsNil)
		doc, err := store.GetIdentity(params.Username(test.identity.Username))
		c.Assert(err, gc.IsNil)
		c.Assert(doc, jc.DeepEquals, test.identity)
	}
}

var addGroupsTests = []struct {
	about        string
	startGroups  []string
	addGroups    []string
	expectGroups []string
	expectErr    string
}{{
	about:        "add groups",
	startGroups:  []string{"test1", "test2"},
	addGroups:    []string{"test3", "test4"},
	expectGroups: []string{"test1", "test2", "test3", "test4"},
}, {
	about:        "overlapping groups",
	startGroups:  []string{"test1", "test2"},
	addGroups:    []string{"test2", "test3"},
	expectGroups: []string{"test1", "test2", "test3"},
}, {
	about:        "same groups",
	startGroups:  []string{"test1", "test2"},
	addGroups:    []string{"test1", "test2"},
	expectGroups: []string{"test1", "test2"},
}, {
	about:        "empty start",
	startGroups:  []string{},
	addGroups:    []string{"test1", "test2"},
	expectGroups: []string{"test1", "test2"},
}, {
	about:        "empty add",
	startGroups:  []string{"test1", "test2"},
	addGroups:    []string{},
	expectGroups: []string{"test1", "test2"},
}, {
	about:        "add dedupes",
	startGroups:  []string{"test1", "test2"},
	addGroups:    []string{"test3", "test3"},
	expectGroups: []string{"test1", "test2", "test3"},
}, {
	about:       "no user",
	startGroups: nil,
	addGroups:   []string{"test1", "test2"},
	expectErr:   `user ".*" not found: not found`,
}}

func (s *storeSuite) TestAddGroups(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)

	for i, test := range addGroupsTests {
		c.Logf("%d: %s", i, test.about)
		username := params.Username(fmt.Sprintf("test-%d", i))
		if test.startGroups != nil {
			err := store.UpsertUser(&mongodoc.Identity{
				Username:   string(username),
				ExternalID: "http://example.com/" + string(username),
				Groups:     test.startGroups,
			})
			c.Assert(err, gc.IsNil)
		}
		err := store.AddGroups(username, test.addGroups)
		if test.expectErr != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErr)
			continue
		}
		c.Assert(err, gc.IsNil)
		doc, err := store.GetIdentity(username)
		c.Assert(err, gc.IsNil)
		sort.Strings(doc.Groups)
		c.Assert(doc.Groups, jc.DeepEquals, test.expectGroups)
	}
}

var removeGroupsTests = []struct {
	about        string
	startGroups  []string
	removeGroups []string
	expectGroups []string
	expectErr    string
}{{
	about:        "remove groups",
	startGroups:  []string{"test1", "test2"},
	removeGroups: []string{"test2"},
	expectGroups: []string{"test1"},
}, {
	about:        "overlapping groups",
	startGroups:  []string{"test1", "test2"},
	removeGroups: []string{"test2", "test3"},
	expectGroups: []string{"test1"},
}, {
	about:        "all groups",
	startGroups:  []string{"test1", "test2"},
	removeGroups: []string{"test1", "test2"},
	expectGroups: []string{},
}, {
	about:        "empty start",
	startGroups:  []string{},
	removeGroups: []string{"test1", "test2"},
	expectGroups: []string{},
}, {
	about:        "empty remove",
	startGroups:  []string{"test1", "test2"},
	removeGroups: []string{},
	expectGroups: []string{"test1", "test2"},
}, {
	about:        "no groups found remove",
	startGroups:  []string{"test1", "test2"},
	removeGroups: []string{"test3", "test4"},
	expectGroups: []string{"test1", "test2"},
}, {
	about:        "remove many",
	startGroups:  []string{"test1", "test2", "test2"},
	removeGroups: []string{"test2"},
	expectGroups: []string{"test1"},
}, {
	about:        "no user",
	startGroups:  nil,
	removeGroups: []string{"test1", "test2"},
	expectErr:    `user ".*" not found: not found`,
}}

func (s *storeSuite) TestRemoveGroups(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)

	for i, test := range removeGroupsTests {
		c.Logf("%d: %s", i, test.about)
		username := params.Username(fmt.Sprintf("test-%d", i))
		if test.startGroups != nil {
			err := store.UpsertUser(&mongodoc.Identity{
				Username:   string(username),
				ExternalID: "http://example.com/" + string(username),
				Groups:     test.startGroups,
			})
			c.Assert(err, gc.IsNil)
		}
		err := store.RemoveGroups(username, test.removeGroups)
		if test.expectErr != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErr)
			continue
		}
		c.Assert(err, gc.IsNil)
		doc, err := store.GetIdentity(username)
		c.Assert(err, gc.IsNil)
		sort.Strings(doc.Groups)
		c.Assert(doc.Groups, jc.DeepEquals, test.expectGroups)
	}
}

var updatePublicKeysIdentityTests = []struct {
	about     string
	identity  *mongodoc.Identity
	expectErr string
}{{
	about: "update existing agent",
	identity: &mongodoc.Identity{
		Username: "existing-agent@owner",
		Groups: []string{
			"test",
			"test2",
		},
		Owner: "owner",
		PublicKeys: []mongodoc.PublicKey{
			{Key: []byte("0000000000000000000000000000000")},
			{Key: []byte("1111111111111111111111111111111")},
		},
	},
}, {
	about: "update a non existing agent",
	identity: &mongodoc.Identity{
		Username:   "non-existing-agent@owner",
		ExternalID: "",
		Email:      "existing@example.com",
		FullName:   "Existing User",
		Groups: []string{
			"test",
			"test2",
		},
		Owner: "owner",
		PublicKeys: []mongodoc.PublicKey{
			{Key: []byte("0000000000000000000000000000000")},
		},
	},
	expectErr: "user \"non-existing-agent@owner\" not found: not found",
}}

func (s *storeSuite) TestUpdatePublicKeys(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)

	// Add existing agent user
	err := store.UpsertAgent(&mongodoc.Identity{
		Username: "existing-agent@owner",
		Groups: []string{
			"test",
			"test2",
		},
		Owner: "owner",
		PublicKeys: []mongodoc.PublicKey{
			{Key: []byte("0000000000000000000000000000000")},
		},
	})
	c.Assert(err, gc.IsNil)

	for i, test := range updatePublicKeysIdentityTests {
		c.Logf("%d: %s", i, test.about)
		err := store.SetPublicKeys(test.identity.Username, test.identity.PublicKeys)
		if test.expectErr != "" {
			c.Assert(err, gc.ErrorMatches, test.expectErr)
			continue
		}
		c.Assert(err, gc.IsNil)
		doc, err := store.GetIdentity(params.Username(test.identity.Username))
		c.Assert(err, gc.IsNil)
		c.Assert(doc, jc.DeepEquals, test.identity)
	}
}

func (s *storeSuite) TestSetGroupsDedupeGroups(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)

	// Add interactive user.
	id := &mongodoc.Identity{
		Username:   "test",
		ExternalID: "http://example.com/test",
		Email:      "test@example.com",
		FullName:   "Test User",
		Groups: []string{
			"test",
		},
	}
	err := store.UpsertUser(id)
	c.Assert(err, gc.IsNil)
	err = store.SetGroups(params.Username(id.Username), []string{"test", "test2", "test2"})
	c.Assert(err, gc.IsNil)

	expect := &mongodoc.Identity{
		Username:   "test",
		ExternalID: "http://example.com/test",
		Email:      "test@example.com",
		FullName:   "Test User",
		Groups: []string{
			"test",
			"test2",
		},
	}

	var doc mongodoc.Identity
	err = store.DB.Identities().Find(bson.D{{"username", "test"}}).One(&doc)
	c.Assert(err, gc.IsNil)
	c.Assert(&doc, jc.DeepEquals, expect)
}

func (s *storeSuite) TestCollections(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	colls := store.DB.Collections()
	names, err := store.DB.CollectionNames()
	c.Assert(err, gc.IsNil)

	// Some collections don't have indexes so they are created only when used.
	createdOnUse := map[string]bool{
		"identity_providers": true,
	}

	// Check that all collections mentioned are actually created.
	for _, coll := range colls {
		found := false
		for _, name := range names {
			if name == coll.Name || createdOnUse[coll.Name] {
				found = true
			}
		}
		if !found {
			c.Errorf("collection %q not created", coll.Name)
		}
	}

	// Check that all created collections are mentioned in Collections.
	for _, name := range names {
		if name == "system.indexes" || name == "managedStoredResources" || name == "macaroons" {
			continue
		}
		found := false
		for _, coll := range colls {
			if coll.Name == name {
				found = true
			}
		}
		if !found {
			c.Errorf("extra collection %q found", name)
		}
	}
}

func (s *storeSuite) TestGetIdentity(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)

	// Add an identity to the store.
	err := store.UpsertUser(&mongodoc.Identity{
		Username:   "test",
		ExternalID: "http://example.com/test",
		Email:      "test@example.com",
		FullName:   "Test User",
		Groups: []string{
			"test",
		},
	})
	c.Assert(err, gc.IsNil)

	// Get the identity from the store
	id, err := store.GetIdentity(params.Username("test"))
	c.Assert(err, gc.IsNil)
	c.Assert(id.Username, gc.Equals, "test")
	c.Assert(id.ExternalID, gc.Equals, "http://example.com/test")
	c.Assert(id.Email, gc.Equals, "test@example.com")
	c.Assert(id.FullName, gc.Equals, "Test User")
	c.Assert(id.Groups, gc.DeepEquals, []string{"test"})

	// Get an identity not in the store
	id, err = store.GetIdentity(params.Username("noone"))
	c.Assert(id, gc.IsNil)
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrNotFound)
}

func (s *storeSuite) TestUpdateIdentity(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)

	// Add an identity to the store.
	err := store.UpsertUser(&mongodoc.Identity{
		Username:   "test",
		ExternalID: "http://example.com/test",
		Email:      "test@example.com",
		FullName:   "Test User",
		Groups: []string{
			"test",
		},
	})
	c.Assert(err, gc.IsNil)

	// Update the identity in the store
	err = store.UpdateIdentity(params.Username("test"), bson.D{{"$set", bson.D{{"extrainfo.foo", []byte("true")}}}})
	c.Assert(err, gc.IsNil)
	id, err := store.GetIdentity(params.Username("test"))
	c.Assert(err, gc.IsNil)
	c.Assert(id.Username, gc.Equals, "test")
	c.Assert(id.ExternalID, gc.Equals, "http://example.com/test")
	c.Assert(id.Email, gc.Equals, "test@example.com")
	c.Assert(id.FullName, gc.Equals, "Test User")
	c.Assert(id.Groups, gc.DeepEquals, []string{"test"})
	c.Assert(id.ExtraInfo, gc.DeepEquals, map[string][]byte{"foo": []byte("true")})

	// Update an identity not in the store.
	err = store.UpdateIdentity(params.Username("noone"), bson.D{{"$set", bson.D{{"extrainfo.foo", []byte("false")}}}})
	c.Assert(errgo.Cause(err), gc.Equals, params.ErrNotFound)
}

func (s *storeSuite) TestUpdateGroupsDoesntEraseSSHKeys(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)

	// Add an identity to the store.
	err := store.UpsertUser(&mongodoc.Identity{
		Username:   "test",
		ExternalID: "http://example.com/test",
		Email:      "test@example.com",
		FullName:   "Test User",
		Groups: []string{
			"test",
		},
		SSHKeys: []string{"345ADASD34", "6745SDADSA"},
	})
	c.Assert(err, gc.IsNil)

	id, err := store.GetIdentity(params.Username("test"))
	c.Assert(id.SSHKeys, gc.DeepEquals, []string{"345ADASD34", "6745SDADSA"})

	err = store.SetGroups("test", []string{"test", "test2"})
	c.Assert(err, gc.IsNil)

	id, err = store.GetIdentity(params.Username("test"))
	c.Assert(err, gc.IsNil)
	c.Assert(id.SSHKeys, gc.DeepEquals, []string{"345ADASD34", "6745SDADSA"})
	c.Assert(id.Groups, gc.DeepEquals, []string{"test", "test2"})
}

func (s *storeSuite) TestGetLaunchpadGroups(c *gc.C) {
	var lp *httptest.Server
	lp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Logf("path: %s", r.URL.Path)
		switch r.URL.Path {
		case "/people":
			r.ParseForm()
			c.Check(r.Form.Get("ws.op"), gc.Equals, "getByOpenIDIdentifier")
			c.Check(r.Form.Get("identifier"), gc.Equals, "https://login.ubuntu.com/+id/test")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"name": "test", "super_teams_collection_link": "%s/test/super_teams"}`, lp.URL)
		case "/test/super_teams":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"total_size":3,"start":0,"entries": [{"name": "test1"},{"name":"test2"}]}`)
		}
	}))
	defer lp.Close()
	lpGroups := store.NewLaunchpadGroups(lpad.APIBase(lp.URL), 0)

	groups, err := lpGroups.GetGroups("https://login.ubuntu.com/+id/test")
	c.Assert(err, gc.IsNil)
	c.Assert(groups, jc.DeepEquals, []string{"test1", "test2"})
}

func (s *storeSuite) TestGetStoreFromPool(c *gc.C) {
	p, err := store.NewPool(s.Session.Copy().DB("store-launchpad-tests"),
		store.StoreParams{
			MaxMgoSessions: 2,
			PrivateAddr:    "localhost",
		},
	)
	c.Assert(err, gc.IsNil)
	defer p.Close()
	s1, err := p.Get()
	c.Assert(err, gc.IsNil)
	s2, err := p.Get()
	c.Assert(err, gc.IsNil)
	defer p.Put(s2)
	p.Put(s1)
	s3, err := p.Get()
	c.Assert(err, gc.IsNil)
	defer p.Put(s3)
	c.Assert(s3.DB.Database.Session, gc.Equals, s1.DB.Database.Session)
}

func (s *storeSuite) TestGetStoreFromPoolLimit(c *gc.C) {
	p, err := store.NewPool(s.Session.Copy().DB("store-launchpad-tests"),
		store.StoreParams{
			MaxMgoSessions: 1,
			RequestTimeout: 100 * time.Millisecond,
			PrivateAddr:    "localhost",
		},
	)
	c.Assert(err, gc.IsNil)
	defer p.Close()
	s1, err := p.Get()
	c.Assert(err, gc.IsNil)
	defer p.Put(s1)
	_, err = p.Get()
	c.Assert(err, gc.ErrorMatches, "too many mongo sessions in use: pool limit exceeded")
}

func (s *storeSuite) TestGetStoreFromPoolPutBeforeTimeout(c *gc.C) {
	p, err := store.NewPool(s.Session.Copy().DB("store-launchpad-tests"),
		store.StoreParams{
			MaxMgoSessions: 1,
			RequestTimeout: time.Second,
			PrivateAddr:    "localhost",
		},
	)
	c.Assert(err, gc.IsNil)
	defer p.Close()
	s1, err := p.Get()
	c.Assert(err, gc.IsNil)
	s1Session := s1.DB.Session
	go func() {
		time.Sleep(500 * time.Millisecond)
		p.Put(s1)
	}()
	s2, err := p.Get()
	c.Assert(err, gc.IsNil)
	defer p.Put(s2)
	c.Assert(s2.DB.Session, gc.Equals, s1Session)
}

func (s *storeSuite) TestCollectionCountsMonitor(c *gc.C) {
	store := s.pool.GetNoLimit()
	defer s.pool.Put(store)
	// Add existing interactive user.
	err := store.UpsertUser(&mongodoc.Identity{
		Username:   "existing",
		ExternalID: "http://example.com/existing",
		Email:      "existing@example.com",
	})
	c.Assert(err, gc.IsNil)

	identitiesCount, err := store.DB.Identities().Count()
	c.Assert(err, gc.IsNil)
	// We've just inserted an identity and the admin user always has an entry.
	c.Assert(identitiesCount, gc.Equals, 2)

	srv := httptest.NewServer(prometheus.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
	defer resp.Body.Close()
	counts := make(map[string]float64)
	for scan := bufio.NewScanner(resp.Body); scan.Scan(); {
		t := scan.Text()
		c.Logf("line %s", t)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if i := strings.Index(t, "{"); i >= 0 {
			j := strings.LastIndex(t, "}")
			t = t[0:i] + t[j+1:]
		}
		fields := strings.Fields(t)
		if len(fields) != 2 {
			c.Logf("unexpected prometheus line %q", scan.Text())
			continue
		}
		f, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			c.Logf("bad value in prometheus line %q", scan.Text())
			continue
		}
		counts[fields[0]] += f
	}

	expectCounts := map[string]int{
		"identities": 2,
		"meeting":    0,
		"macaroons":  0,
	}
	for name, count := range expectCounts {
		name = "blues_identity_collection_" + name + "_count"
		got, ok := counts[name]
		c.Assert(ok, gc.Equals, true, gc.Commentf("%s", name))
		c.Check(math.Trunc(got), gc.Equals, float64(count), gc.Commentf("%s", name))
	}
}

type nopCloser struct{}

func (nopCloser) Close() {}
