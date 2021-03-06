package memstore_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/aclstore/v2"
	"github.com/juju/simplekv/memsimplekv"

	"github.com/canonical/candid/v2/meeting"
	"github.com/canonical/candid/v2/store"
	"github.com/canonical/candid/v2/store/memstore"
	"github.com/canonical/candid/v2/store/storetest"
)

func TestKeyValueStore(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	storetest.TestKeyValueStore(c, func(c *qt.C) store.ProviderDataStore {
		return memstore.NewProviderDataStore()
	})
}

func TestStore(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	storetest.TestStore(c, func(c *qt.C) store.Store {
		return memstore.NewStore()
	})
}

func TestMeetingStore(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	storetest.TestMeetingStore(c, func(c *qt.C) meeting.Store {
		return memstore.NewMeetingStore()
	}, memstore.PutAtTime)
}

func TestACLStore(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	storetest.TestACLStore(c, func(c *qt.C) aclstore.ACLStore {
		return aclstore.NewACLStore(memsimplekv.NewStore())
	})
}

func TestConfigUnmarshal(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	storetest.TestUnmarshal(c, `
storage:
    type: memory
`)
}
