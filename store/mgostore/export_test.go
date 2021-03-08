// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package mgostore

import (
	"context"
	"time"

	"gopkg.in/canonical/candid.v2/meeting"
)

var PutAtTime = func(ctx context.Context, s meeting.Store, id, address string, now time.Time) error {
	return s.(*meetingStore).put(ctx, id, address, now)
}
