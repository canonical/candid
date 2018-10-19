package memstore

import (
	"github.com/juju/aclstore/v2"
	"github.com/juju/simplekv/memsimplekv"
	"github.com/juju/utils/debugstatus"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/candid/meeting"
	"github.com/CanonicalLtd/candid/store"
)

func init() {
	store.Register("memory", func(func(interface{}) error) (store.BackendFactory, error) {
		return &backend{
			store:        NewStore(),
			rootKeys:     bakery.NewMemRootKeyStore(),
			providerData: NewProviderDataStore(),
			meetingStore: NewMeetingStore(),
			aclStore:     aclstore.NewACLStore(memsimplekv.NewStore()),
		}, nil
	})
}

type backend struct {
	store        store.Store
	providerData store.ProviderDataStore
	rootKeys     bakery.RootKeyStore
	meetingStore meeting.Store
	aclStore     aclstore.ACLStore
}

// NewBackend implements store.BackendFactory.NewBackend.
func (b *backend) NewBackend() (store.Backend, error) {
	return b, nil
}

// ProviderDataStore implements store.Backend.ProviderDataStore.
func (b *backend) ProviderDataStore() store.ProviderDataStore {
	return b.providerData
}

// Store implements store.Backend.Store.
func (b *backend) Store() store.Store {
	return b.store
}

// BakeryRootKeyStore implements store.Backend.BakeryRootKeyStore.
func (b *backend) BakeryRootKeyStore() bakery.RootKeyStore {
	return b.rootKeys
}

// DebugStatusCheckerFuncs implements store.Backend.DebugStatusCheckerFuncs.
func (b *backend) DebugStatusCheckerFuncs() []debugstatus.CheckerFunc {
	return nil
}

// MeetingStore implements store.Backend.MeetingStore.
func (b *backend) MeetingStore() meeting.Store {
	return b.meetingStore
}

func (b *backend) ACLStore() aclstore.ACLStore {
	return b.aclStore
}

func (b *backend) Close() {
}
