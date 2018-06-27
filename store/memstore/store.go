// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package memstore provides an in-memory implementation of the store.
// This might be useful for simple test systems.
package memstore

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/candid/store"
)

type memStore struct {
	mu         sync.Mutex
	identities []*store.Identity
}

// NewStore creates a new in-memory store.Store instance.
func NewStore() store.Store {
	return &memStore{}
}

// Context implements store.Store.Context by returning the given context
// and a NOP close function.
func (s *memStore) Context(ctx context.Context) (_ context.Context, cancel func()) {
	return ctx, func() {}
}

var adminID = store.MakeProviderIdentity("idm", "admin")

// RemoveAll is implemented so that tests can clear out the data.
// It removes all identities except the admin identity created at
// init time.
// TODO provide a standard store.Store way of removing
// identities.
func (s *memStore) RemoveAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	var identities []*store.Identity
	for _, identity := range s.identities {
		if identity.ProviderID == adminID {
			identities = append(identities, identity)
		}
	}
	s.identities = identities
}

// Identity implements store.Store.Identity.
func (s *memStore) Identity(_ context.Context, identity *store.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id *store.Identity
	switch {
	case identity.ID != "":
		n, err := strconv.Atoi(identity.ID)
		if err != nil || n >= len(s.identities) {
			return store.NotFoundError(identity.ID, "", "")
		}
		id = s.identities[n]
	case identity.ProviderID != "":
		id = s.identityFromProviderID(identity.ProviderID)
		if id == nil {
			return store.NotFoundError("", identity.ProviderID, "")
		}
	case identity.Username != "":
		id = s.identityFromUsername(identity.Username)
		if id == nil {
			return store.NotFoundError("", "", identity.Username)
		}
	default:
		return store.NotFoundError("", "", "")
	}
	copyIdentity(identity, id)
	return nil
}

// identityFromProviderID performs a linear search to find an identitty
// with the given providerID.
func (s *memStore) identityFromProviderID(providerID store.ProviderIdentity) *store.Identity {
	for _, id := range s.identities {
		if id.ProviderID == providerID {
			return id
		}
	}
	return nil
}

// identityFromUsername performs a linear search to find an identitty
// with the given username.
func (s *memStore) identityFromUsername(username string) *store.Identity {
	for _, id := range s.identities {
		if id.Username == username {
			return id
		}
	}
	return nil
}

// FindIdentities implements store.Store.FindIdentities.
func (s *memStore) FindIdentities(ctx context.Context, ref *store.Identity, filter store.Filter, sortFields []store.Sort, skip, limit int) ([]store.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identities := make([]store.Identity, 0, len(s.identities))
	for _, identity := range s.identities {
		if !matchIdentity(identity, ref, filter) {
			continue
		}
		var identity1 store.Identity
		copyIdentity(&identity1, identity)
		identities = append(identities, identity1)
	}
	if skip > len(identities) {
		return nil, nil
	}
	if len(sortFields) > 0 {
		sort.Sort(identitySort{
			identities: identities,
			sort:       sortFields,
		})
	}
	identities = identities[skip:]
	if limit > 0 && limit < len(identities) {
		identities = identities[:limit]
	}
	return identities, nil
}

func matchIdentity(a, b *store.Identity, filter store.Filter) bool {
	for f, c := range filter {
		if c == store.NoComparison {
			continue
		}
		var r int
		switch store.Field(f) {
		case store.ProviderID:
			r = strings.Compare(string(a.ProviderID), string(b.ProviderID))
		case store.Username:
			r = strings.Compare(a.Username, b.Username)
		case store.Name:
			r = strings.Compare(a.Name, b.Name)
		case store.Email:
			r = strings.Compare(a.Email, b.Email)
		case store.LastLogin:
			r = cmpTime(a.LastLogin, b.LastLogin)
		case store.LastDischarge:
			r = cmpTime(a.LastDischarge, b.LastDischarge)
		default:
			panic("unsupported filter field")
		}
		if !matchCmp(r, c) {
			return false
		}
	}
	return true
}

// matchCmp determines whether the given value n which is a result of a
// "cmp" function such as strings.Compare indicates that the compared
// values have the relationship specified by the given store.Comparison.
func matchCmp(n int, c store.Comparison) bool {
	switch c {
	case store.Equal:
		return n == 0
	case store.NotEqual:
		return n != 0
	case store.GreaterThan:
		return n > 0
	case store.LessThan:
		return n < 0
	case store.GreaterThanOrEqual:
		return n >= 0
	case store.LessThanOrEqual:
		return n <= 0
	default:
		panic("unsupported comparison")
	}
}

func cmpTime(t, u time.Time) int {
	if t.After(u) {
		return 1
	}
	if t.Before(u) {
		return -1
	}
	return 0
}

type identitySort struct {
	identities []store.Identity
	sort       []store.Sort
}

func (s identitySort) Len() int {
	return len(s.identities)
}

func (s identitySort) Swap(i, j int) {
	s.identities[i], s.identities[j] = s.identities[j], s.identities[i]
}

func (s identitySort) Less(i, j int) bool {
	a := &s.identities[i]
	b := &s.identities[j]
	for _, sort := range s.sort {
		switch s.cmp(a, b, sort.Field, sort.Descending) {
		case 1:
			return false
		case -1:
			return true
		}
	}
	return false
}

func (s identitySort) cmp(a, b *store.Identity, f store.Field, desc bool) int {
	cmp := 0
	switch f {
	case store.ProviderID:
		cmp = strings.Compare(string(a.ProviderID), string(b.ProviderID))
	case store.Username:
		cmp = strings.Compare(a.Username, b.Username)
	case store.Name:
		cmp = strings.Compare(a.Name, b.Name)
	case store.Email:
		cmp = strings.Compare(a.Email, b.Email)
	case store.LastLogin:
		cmp = cmpTime(a.LastLogin, b.LastLogin)
	case store.LastDischarge:
		cmp = cmpTime(a.LastDischarge, b.LastDischarge)
	default:
		panic("unsupported sort field")
	}
	if desc {
		return 0 - cmp
	}
	return cmp
}

// UpdateIdentity implements store.Store.UpdateIdentity.
func (s *memStore) UpdateIdentity(_ context.Context, identity *store.Identity, update store.Update) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id *store.Identity
	switch {
	case identity.ID != "":
		n, err := strconv.Atoi(identity.ID)
		if err != nil || n >= len(s.identities) {
			return store.NotFoundError(identity.ID, "", "")
		}
		id = s.identities[n]
	case identity.ProviderID != "":
		id = s.identityFromProviderID(identity.ProviderID)
		if id == nil {
			if identity.Username == "" || update[store.Username] == store.NoUpdate {
				return store.NotFoundError("", identity.ProviderID, "")
			}
			n := len(s.identities)
			id = &store.Identity{
				ID:           fmt.Sprintf("%d", n),
				ProviderID:   identity.ProviderID,
				ProviderInfo: make(map[string][]string),
				ExtraInfo:    make(map[string][]string),
			}
			if err := s.updateIdentity(id, identity, update); err != nil {
				return errgo.Mask(err, errgo.Is(store.ErrDuplicateUsername))
			}
			s.identities = append(s.identities, id)
			identity.ID = id.ID
			return nil
		}
	case identity.Username != "":
		id = s.identityFromUsername(identity.Username)
		if id == nil {
			return store.NotFoundError("", "", identity.Username)
		}
	default:
		return store.NotFoundError("", "", "")
	}
	return errgo.Mask(s.updateIdentity(id, identity, update), errgo.Is(store.ErrDuplicateUsername))
}

func (s *memStore) updateIdentity(dst, src *store.Identity, update store.Update) error {
	if update[store.ProviderID] != store.NoUpdate {
		panic(errgo.Newf("unsupported operation %v requested on ProviderID field", update[store.ProviderID]))
	}
	switch update[store.Username] {
	case store.NoUpdate:
	case store.Set:
		id := s.identityFromUsername(src.Username)
		if id != nil && id != dst {
			return store.DuplicateUsernameError(src.Username)
		}
		dst.Username = src.Username
	default:
		panic("unsupported operation requested on Username field")
	}
	dst.Name = updateString(dst.Name, src.Name, update[store.Name])
	dst.Email = updateString(dst.Email, src.Email, update[store.Email])
	dst.Groups = updateStrings(dst.Groups, src.Groups, update[store.Groups])
	dst.PublicKeys = updateKeys(dst.PublicKeys, src.PublicKeys, update[store.PublicKeys])
	dst.LastDischarge = updateTime(dst.LastDischarge, src.LastDischarge, update[store.LastDischarge])
	dst.LastLogin = updateTime(dst.LastLogin, src.LastLogin, update[store.LastLogin])
	dst.ProviderInfo = updateMap(dst.ProviderInfo, src.ProviderInfo, update[store.ProviderInfo])
	dst.ExtraInfo = updateMap(dst.ExtraInfo, src.ExtraInfo, update[store.ExtraInfo])
	return nil
}

func updateString(dst, src string, op store.Operation) string {
	switch op {
	case store.NoUpdate:
		return dst
	case store.Set:
		return src
	case store.Clear:
		return ""
	default:
		panic("unsupported operation requested on string field")
	}
}

func updateTime(dst, src time.Time, op store.Operation) time.Time {
	switch op {
	case store.NoUpdate:
		return dst
	case store.Set:
		return src
	case store.Clear:
		return time.Time{}
	default:
		panic("unsupported operation requested on string field")
	}
}

func updateStrings(dst, src []string, op store.Operation) []string {
	switch op {
	case store.NoUpdate:
		return dst
	case store.Set:
		return append([]string(nil), src...)
	case store.Clear:
		return nil
	case store.Push:
		for _, s := range src {
			if !containsString(dst, s) {
				dst = append(dst, s)
			}
		}
		return dst
	case store.Pull:
		var ndst []string
		for _, s := range dst {
			if !containsString(src, s) {
				ndst = append(ndst, s)
			}
		}
		return ndst
	default:
		panic("unsupported operation requested on []string field")
	}
}

func containsString(ss []string, s string) bool {
	for _, t := range ss {
		if s == t {
			return true
		}
	}
	return false
}

func updateKeys(dst, src []bakery.PublicKey, op store.Operation) []bakery.PublicKey {
	switch op {
	case store.NoUpdate:
		return dst
	case store.Set:
		return append([]bakery.PublicKey(nil), src...)
	case store.Clear:
		return nil
	case store.Push:
		for _, k := range src {
			if !containsKey(dst, k) {
				dst = append(dst, k)
			}
		}
		return dst
	case store.Pull:
		var ndst []bakery.PublicKey
		for _, k := range dst {
			if !containsKey(src, k) {
				ndst = append(ndst, k)
			}
		}
		return ndst
	default:
		panic("unsupported operation requested on []bakery.PublicKey field")
	}
}

func containsKey(ks []bakery.PublicKey, k bakery.PublicKey) bool {
	for _, k1 := range ks {
		if k == k1 {
			return true
		}
	}
	return false
}

func updateMap(dst, src map[string][]string, op store.Operation) map[string][]string {
	for k, v := range src {
		ss := updateStrings(dst[k], v, op)
		if len(ss) == 0 {
			delete(dst, k)
		} else {
			dst[k] = ss
		}
	}
	return dst
}

func copyIdentity(dst, src *store.Identity) {
	*dst = *src
	dst.Groups = updateStrings(nil, src.Groups, store.Set)
	dst.PublicKeys = updateKeys(nil, src.PublicKeys, store.Set)
	dst.ProviderInfo = updateMap(make(map[string][]string), src.ProviderInfo, store.Set)
	dst.ExtraInfo = updateMap(make(map[string][]string), src.ExtraInfo, store.Set)
}

// IdentityCounts implements store.Store.IdentityCounts.
func (s *memStore) IdentityCounts(_ context.Context) (map[string]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := make(map[string]int)
	for _, id := range s.identities {
		counts[id.ProviderID.Provider()]++
	}
	return counts, nil
}
