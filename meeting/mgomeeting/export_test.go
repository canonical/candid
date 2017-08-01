// Copyright 2015 Canonical Ltd.

package mgomeeting

import (
	"time"

	"golang.org/x/net/context"
)

var PutAtTime = func(ctx context.Context, s *Store, id, address string, now time.Time) error {
	return s.put(ctx, id, address, now)
}
