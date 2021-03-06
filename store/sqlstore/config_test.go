package sqlstore_test

import (
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/candid/v2/store/storetest"
)

func TestConfigUnmarshal(t *testing.T) {
	c := qt.New(t)
	defer c.Done()

	f := newFixture(c)
	storetest.TestUnmarshal(c, `
storage:
    type: postgres
    connection-string: 'search_path=`+f.pg.Schema()+`'
`)
}
