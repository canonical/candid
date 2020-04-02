// Copyright 2015 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE.client file for details.

package candidclient

import (
	"strings"
	"time"

	"gopkg.in/errgo.v1"
)

// TODO unexport this type - it's best exposed as part of the client API only.

// PermChecker provides a way to query ACLs using the identity client.
type PermChecker struct {
	cache *GroupCache
}

// NewPermChecker returns a permission checker
// that uses the given identity client to check permissions.
//
// It will cache results for at most cacheTime.
func NewPermChecker(c *Client, cacheTime time.Duration) *PermChecker {
	return &PermChecker{
		cache: NewGroupCache(c, cacheTime),
	}
}

// NewPermCheckerWithCache returns a new PermChecker using
// the given cache for its group queries.
func NewPermCheckerWithCache(cache *GroupCache) *PermChecker {
	return &PermChecker{
		cache: cache,
	}
}

// trivialAllow reports whether the username should be allowed
// access to the given ACL based on a superficial inspection
// of the ACL. If there is a definite answer, it will return
// a true isTrivial; otherwise it will return (false, false).
func trivialAllow(username string, acl []string) (allow, isTrivial bool) {
	if len(acl) == 0 {
		return false, true
	}
	for _, name := range acl {
		if name == username {
			return true, true
		}
		suffix := strings.TrimPrefix(name, "everyone")
		if len(suffix) == len(name) {
			continue
		}
		if suffix != "" && suffix[0] != '@' {
			continue
		}
		// name is either "everyone" or "everyone@somewhere". We consider
		// the user to be part of everyone@somewhere if their username has
		// the suffix @somewhere.
		if strings.HasSuffix(username, suffix) {
			return true, true
		}
	}
	return false, false
}

// Allow reports whether the given ACL admits the user with the given
// name. If the user does not exist and the ACL does not allow username
// or everyone, it will return (false, nil).
func (c *PermChecker) Allow(username string, acl []string) (bool, error) {
	if ok, isTrivial := trivialAllow(username, acl); isTrivial {
		return ok, nil
	}
	groups, err := c.cache.groupMap(username)
	if err != nil {
		return false, errgo.Mask(err)
	}
	for _, a := range acl {
		if groups[a] {
			return true, nil
		}
	}
	return false, nil
}

// CacheEvict evicts username from the cache.
func (c *PermChecker) CacheEvict(username string) {
	c.cache.CacheEvict(username)
}

// CacheEvictAll evicts everything from the cache.
func (c *PermChecker) CacheEvictAll() {
	c.cache.CacheEvictAll()
}
