// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"github.com/juju/simplekv"

	"gopkg.in/canonical/candid.v2/idp"
	"gopkg.in/canonical/candid.v2/internal/discharger/internal"
	"gopkg.in/canonical/candid.v2/internal/identity"
	"gopkg.in/canonical/candid.v2/store"
)

var NewIDPHandler = newIDPHandler

type LoginInfo loginInfo

func NewVisitCompleter(params identity.HandlerParams, kvstore simplekv.Store, store store.Store) idp.VisitCompleter {
	return &visitCompleter{
		params:        params,
		identityStore: internal.NewIdentityStore(kvstore, store),
		place:         &place{params.MeetingPlace},
	}
}
