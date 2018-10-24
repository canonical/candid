package store

import (
	"github.com/juju/aclstore/v2"
	"github.com/juju/utils/debugstatus"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/candid/meeting"
)

var backends = make(map[string]func(func(interface{}) error) (BackendFactory, error))

// Backend is the interface provided by a storage backend
// implementation. Backend instances should be closed after use.
type Backend interface {
	// ProviderDataStore returns a new ProviderDataStore
	// implementation that uses the backend.
	ProviderDataStore() ProviderDataStore

	// BakeryRootKeyStore returns a new bakery.RootKeyStore
	// implementation that uses the backend.
	BakeryRootKeyStore() bakery.RootKeyStore

	// MeetingStore returns a new meeting.Store implementation
	// that uses the backend.
	MeetingStore() meeting.Store

	// DebugStatusCheckerFuncs returns a set of
	// debugstatus.CheckerFuncs that can be used to provide a status
	// of the backend in the /debug/status endpoint.
	DebugStatusCheckerFuncs() []debugstatus.CheckerFunc

	// Store returns a new store.Store instance that uses
	// the backend.
	Store() Store

	// ACLStore returns a new aclstore.Store that is used to provide
	// ACLs for system functions.
	ACLStore() aclstore.ACLStore

	// Close closes the Backend instance.
	Close()
}

// BackendFactory represents a value that can create new storage
// backend instances.
type BackendFactory interface {
	NewBackend() (Backend, error)
}

// Register is used by storage backends to register a function
// that can be used to unmarshal parameters for a storage backend. When
// a storage backend with the given type is used, f will be called to
// unmarshal its parameters from YAML. Its argument will be an
// unmarshalYAML function that can be used to unmarshal the
// configuration parameters into its argument according to the rules
// specified in gopkg.in/yaml.v2, and it should return a function that
// can be used to create a storage backend.
func Register(storageType string, f func(func(interface{}) error) (BackendFactory, error)) {
	backends[storageType] = f
}

// Config allows a storage instance to be unmarshaled from a YAML
// configuration file. The "type" field determines which registered
// backend is used for the unmarshaling.
type Config struct {
	BackendFactory
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var t struct {
		Type string
	}
	if err := unmarshal(&t); err != nil {
		return errgo.Notef(err, "cannot unmarshal storage")
	}
	if storageUnmarshaler, ok := backends[t.Type]; ok {
		bf, err := storageUnmarshaler(unmarshal)
		if err != nil {
			return errgo.Notef(err, "cannot unmarshal %s configuration", t.Type)
		}
		c.BackendFactory = bf
		return err
	}
	return errgo.Newf("unrecognised storage backend type %q", t.Type)
}
