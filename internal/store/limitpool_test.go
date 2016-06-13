// Copyright 2016 Canonical Ltd.

package store

import (
	"github.com/CanonicalLtd/blues-identity/internal/limitpool"
)

var _ LimitPool = (*monitoredPool)(nil)
var _ LimitPool = (*limitpool.Pool)(nil)
