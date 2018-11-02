package storetest

import (
	"time"

	"golang.org/x/net/context"
	"gopkg.in/yaml.v2"
	qt "github.com/frankban/quicktest"

	"github.com/CanonicalLtd/candid/store"
)

func TestUnmarshal(c *qt.C, configYAML string) {
	ctx := context.Background()
	var cfg struct {
		Storage *store.Config `yaml:"storage"`
	}
	err := yaml.Unmarshal([]byte(configYAML), &cfg)
	c.Assert(err, qt.Equals, nil)
	c.Assert(cfg.Storage, qt.Not(qt.IsNil))

	backend, err := cfg.Storage.NewBackend()
	c.Assert(err, qt.Equals, nil)
	defer backend.Close()

	// Sanity check that the backend can actually be used.

	kv, err := backend.ProviderDataStore().KeyValueStore(ctx, "test")
	c.Assert(err, qt.Equals, nil)

	err = kv.Set(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, qt.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	result, err := kv.Get(ctx, "test-key")
	c.Assert(err, qt.Equals, nil)
	c.Assert(string(result), qt.Equals, "test-value")
}
