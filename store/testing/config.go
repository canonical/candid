package testing

import (
	"time"

	"github.com/CanonicalLtd/candid/store"
	"golang.org/x/net/context"
	gc "gopkg.in/check.v1"
	"gopkg.in/yaml.v2"
)

func TestUnmarshal(c *gc.C, configYAML string) {
	ctx := context.Background()
	var cfg struct {
		Storage *store.Config `yaml:"storage"`
	}
	err := yaml.Unmarshal([]byte(configYAML), &cfg)
	c.Assert(err, gc.Equals, nil)
	c.Assert(cfg.Storage, gc.NotNil)

	backend, err := cfg.Storage.NewBackend()
	c.Assert(err, gc.Equals, nil)
	defer backend.Close()

	// Sanity check that the backend can actually be used.

	kv, err := backend.ProviderDataStore().KeyValueStore(ctx, "test")
	c.Assert(err, gc.Equals, nil)

	err = kv.Set(ctx, "test-key", []byte("test-value"), time.Time{})
	c.Assert(err, gc.Equals, nil)
	ctx, close := kv.Context(ctx)
	defer close()

	result, err := kv.Get(ctx, "test-key")
	c.Assert(err, gc.Equals, nil)
	c.Assert(string(result), gc.Equals, "test-value")
}
