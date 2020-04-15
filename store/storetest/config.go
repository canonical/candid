package storetest

import (
	"context"
	"time"

	qt "github.com/frankban/quicktest"
	"gopkg.in/yaml.v2"

	"github.com/canonical/candid/store"
)

func TestUnmarshal(c *qt.C, configYAML string) {
	ctx := context.Background()
	var cfg struct {
		Storage *store.Config `yaml:"storage"`
	}
	err := yaml.Unmarshal([]byte(configYAML), &cfg)
	c.Assert(err, qt.IsNil)
	c.Assert(cfg.Storage, qt.Not(qt.IsNil))

	backend, err := cfg.Storage.NewBackend()
	c.Assert(err, qt.IsNil)
	defer backend.Close()

	// Sanity check that the backend can actually be used.

	kv, err := backend.ProviderDataStore().KeyValueStore(ctx, "test")
	c.Assert(err, qt.IsNil)

	err = kv.Set(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, qt.IsNil)
	ctx, close := kv.Context(ctx)
	defer close()

	result, err := kv.Get(ctx, "test-key")
	c.Assert(err, qt.IsNil)
	c.Assert(string(result), qt.Equals, "test-value")
}
