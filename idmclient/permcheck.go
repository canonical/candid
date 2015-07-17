// Copyright 2015 Canonical Ltd.

package idmclient

import (
	"time"

	"github.com/juju/utils/cache"
	"gopkg.in/errgo.v1"

	"github.com/CanonicalLtd/blues-identity/params"
)

// PermChecker provides a way to query ACLs using the identity client.
type PermChecker struct {
	cache  *cache.Cache
	client *Client
}

// NewPermChecker returns a permission checker
// that uses the given identity client to check permissions.
//
// It will cache results for at most cacheTime.
func NewPermChecker(c *Client, cacheTime time.Duration) *PermChecker {
	return &PermChecker{
		cache:  cache.New(cacheTime),
		client: c,
	}
}

// Allow reports whether the given ACL admits the user with the given
// name. If the user does not exist and the ACL does not allow username
// or everyone, it will return (false, nil).
func (c *PermChecker) Allow(username string, acl []string) (bool, error) {
	if len(acl) == 0 {
		return false, nil
	}
	for _, name := range acl {
		if name == "everyone" || name == username {
			return true, nil
		}
	}
	groups0, err := c.cache.Get(username, func() (interface{}, error) {
		groups, err := c.client.UserGroups(&params.UserGroupsRequest{
			Username: params.Username(username),
		})
		if err != nil && errgo.Cause(err) != params.ErrNotFound {
			return nil, errgo.Mask(err)
		}
		groupMap := make(map[string]bool)
		for _, g := range groups {
			groupMap[g] = true
		}
		return groupMap, nil
	})
	if err != nil {
		return false, errgo.Notef(err, "cannot fetch groups")
	}
	groups := groups0.(map[string]bool)
	for _, a := range acl {
		if groups[a] {
			return true, nil
		}
	}
	return false, nil
}

// CacheEvict evicts username from the cache.
func (c *PermChecker) CacheEvict(username string) {
	c.cache.Evict(username)
}

// CacheEvictAll evicts everything from the cache.
func (c *PermChecker) CacheEvictAll() {
	c.cache.EvictAll()
}
