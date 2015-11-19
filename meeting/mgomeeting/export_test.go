// Copyright 2015 Canonical Ltd.

package mgomeeting

import (
	"time"

	"github.com/CanonicalLtd/blues-identity/meeting"
)

var PutAtTime = func(s meeting.Store, id, address string, now time.Time) error {
	return s.(store).put(id, address, now)
}
