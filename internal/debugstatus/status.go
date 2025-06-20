// debugstatus contains the removed contents of the deprecated
// github.com/juju/juju/utils/v2/debugstatus package.
// See https://github.com/juju/utils/pull/320/files .
package debugstatus

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/juju/mgo/v2"
)

// CheckResult holds the result of a single status check.
type CheckResult struct {
	// Name is the human readable name for the check.
	Name string

	// Value is the check result.
	Value string

	// Passed reports whether the check passed.
	Passed bool

	// Duration holds the duration that the
	// status check took to run.
	Duration time.Duration
}

// CheckerFunc represents a function returning the check machine friendly key
// and the result.
type CheckerFunc func(ctx context.Context) (key string, result CheckResult)

// StartTime holds the time that the code started running.
var StartTime = time.Now().UTC()

// Version describes the current version of the code being run.
type Version struct {
	GitCommit string
	Version   string
}

// Collector is an interface that groups the methods used to check that
// a Mongo database has the expected collections.
// It is usually implemented by types extending mgo.Database to add the
// Collections() method.
type Collector interface {
	// Collections returns the Mongo collections that we expect to exist in
	// the Mongo database.
	Collections() []*mgo.Collection

	// CollectionNames returns the names of the collections actually present in
	// the Mongo database.
	CollectionNames() ([]string, error)
}

// Check collects the status check results from the given checkers.
func Check(ctx context.Context, checkers ...CheckerFunc) map[string]CheckResult {
	var mu sync.Mutex
	results := make(map[string]CheckResult, len(checkers))

	var wg sync.WaitGroup
	for _, c := range checkers {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			key, result := c(ctx)
			result.Duration = time.Since(t0)
			mu.Lock()
			results[key] = result
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

// ServerStartTime reports the time when the application was started.
func ServerStartTime(context.Context) (key string, result CheckResult) {
	return "server_started", CheckResult{
		Name:   "Server started",
		Value:  StartTime.String(),
		Passed: true,
	}
}

// MongoCollections returns a status checker checking that all the
// expected Mongo collections are present in the database.
func MongoCollections(c Collector) CheckerFunc {
	return func(context.Context) (key string, result CheckResult) {
		key = "mongo_collections"
		result.Name = "MongoDB collections"
		names, err := c.CollectionNames()
		if err != nil {
			result.Value = "Cannot get collections: " + err.Error()
			return key, result
		}
		var missing []string
		for _, coll := range c.Collections() {
			found := false
			for _, name := range names {
				if name == coll.Name {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, coll.Name)
			}
		}
		if len(missing) == 0 {
			result.Value = "All required collections exist"
			result.Passed = true
			return key, result
		}
		result.Value = fmt.Sprintf("Missing collections: %s", missing)
		return key, result
	}
}
