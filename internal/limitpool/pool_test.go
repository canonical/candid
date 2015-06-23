// Copyright 2015 Canonical Ltd.

package limitpool_test

import (
	"time"

	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/blues-identity/internal/limitpool"
)

type poolSuite struct{}

var _ = gc.Suite(&poolSuite{})

type item struct {
	value  string
	closed bool
}

func (i *item) Close() {
	i.closed = true
}

func (s *poolSuite) TestGetNoLimit(c *gc.C) {
	p := limitpool.NewPool(0, func() limitpool.Item {
		return &item{
			value: "TestGetNoLimit",
		}
	})
	v := p.GetNoLimit().(*item)
	c.Assert(v.value, gc.Equals, "TestGetNoLimit")
}

func (s *poolSuite) TestGetSpareCapacity(c *gc.C) {
	p := limitpool.NewPool(1, func() limitpool.Item {
		return &item{
			value: "TestGetSpareCapacity",
		}
	})
	v, err := p.Get(0)
	c.Assert(err, gc.IsNil)
	c.Assert(v.(*item).value, gc.Equals, "TestGetSpareCapacity")
}

func (s *poolSuite) TestGetTimeout(c *gc.C) {
	p := limitpool.NewPool(0, func() limitpool.Item {
		c.Error("unexpected call to new")
		return nil
	})
	_, err := p.Get(0)
	c.Assert(err, gc.Equals, limitpool.ErrLimitExceeded)
}

func (s *poolSuite) TestGetWaiting(c *gc.C) {
	p := limitpool.NewPool(1, func() limitpool.Item {
		return &item{
			value: "TestGetWaiting",
		}
	})
	v := p.GetNoLimit()
	go func() {
		time.Sleep(10 * time.Millisecond)
		p.Put(v)
	}()
	v1, err := p.Get(5 * time.Second)
	c.Assert(err, gc.IsNil)
	c.Assert(v1, gc.Equals, v)
}

func (s *poolSuite) TestGetStored(c *gc.C) {
	p := limitpool.NewPool(1, func() limitpool.Item {
		return &item{
			value: "TestGetStored",
		}
	})
	v := p.GetNoLimit()
	p.Put(v)
	v1, err := p.Get(0)
	c.Assert(err, gc.IsNil)
	c.Assert(v1, gc.Equals, v)
}

func (s *poolSuite) TestGetClosed(c *gc.C) {
	p := limitpool.NewPool(0, func() limitpool.Item {
		c.Error("unexpected call to new")
		return nil
	})
	p.Close()
	_, err := p.Get(0)
	c.Assert(err, gc.Equals, limitpool.ErrClosed)
}

func (s *poolSuite) TestGetNoLimitClosed(c *gc.C) {
	p := limitpool.NewPool(0, func() limitpool.Item {
		return &item{
			value: "TestGetNoLimitClosed",
		}
	})
	p.Close()
	v := p.GetNoLimit()
	c.Assert(v.(*item).value, gc.Equals, "TestGetNoLimitClosed")
}

func (s *poolSuite) TestAddIncrementsCount(c *gc.C) {
	p := limitpool.NewPool(1, func() limitpool.Item {
		c.Error("unexpected call to new")
		return nil
	})
	p.Add()
	_, err := p.Get(0)
	c.Assert(err, gc.Equals, limitpool.ErrLimitExceeded)
}

func (s *poolSuite) TestPutClosesWhenClosed(c *gc.C) {
	p := limitpool.NewPool(1, func() limitpool.Item {
		return &item{
			value: "TestPutClosesWhenClosed",
		}
	})
	v := p.GetNoLimit()
	p.Close()
	p.Put(v)
	c.Assert(v.(*item).closed, gc.Equals, true)
}

func (s *poolSuite) TestPutClosesWhenOverflowing(c *gc.C) {
	p := limitpool.NewPool(0, func() limitpool.Item {
		return &item{
			value: "TestPutClosesWhenOverflowing",
		}
	})
	v := p.GetNoLimit()
	p.Put(v)
	c.Assert(v.(*item).closed, gc.Equals, true)
}

func (s *poolSuite) TestClosesClosesItemsInThePool(c *gc.C) {
	p := limitpool.NewPool(1, func() limitpool.Item {
		return &item{
			value: "TestClosesClosesItemsInThePool",
		}
	})
	v := p.GetNoLimit()
	p.Put(v)
	c.Assert(v.(*item).closed, gc.Equals, false)
	p.Close()
	c.Assert(v.(*item).closed, gc.Equals, true)
}
