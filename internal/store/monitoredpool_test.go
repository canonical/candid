package store

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/limitpool"
)

type monitoredSessionPoolSuite struct{}

var _ = gc.Suite(&monitoredSessionPoolSuite{})

func (s *monitoredSessionPoolSuite) TestGetIncrements(c *gc.C) {
	var gauge gauge
	pool := newMonitoredSessionPool(&gauge, 3, func() limitpool.Item { return nopCloser{} })
	c.Assert(gauge.GetValue(), gc.Equals, 0)
	i, err := pool.Get(time.Second)
	c.Assert(err, gc.IsNil)
	c.Assert(gauge.GetValue(), gc.Equals, 0)
	pool.Put(i)
	c.Assert(gauge.GetValue(), gc.Equals, 1)
}

func (s *monitoredSessionPoolSuite) TestGetNoLimitIncrements(c *gc.C) {
	var gauge gauge
	pool := newMonitoredSessionPool(&gauge, 3, func() limitpool.Item { return nopCloser{} })
	c.Assert(gauge.GetValue(), gc.Equals, 0)
	i := pool.GetNoLimit()
	c.Assert(gauge.GetValue(), gc.Equals, 0)
	pool.Put(i)
	c.Assert(gauge.GetValue(), gc.Equals, 1)
}

type nopCloser struct{}

func (nopCloser) Close() {}

type gauge struct {
	sync.Mutex
	prometheus.Gauge

	value int
}

func (g *gauge) Inc() {
	g.Lock()
	g.value++
	g.Unlock()
}

func (g *gauge) Dec() {
	g.Lock()
	g.value--
	g.Unlock()
}

func (g *gauge) GetValue() int {
	g.Lock()
	defer g.Unlock()
	return g.value
}
