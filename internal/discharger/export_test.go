// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/internal/discharger/internal"
	"github.com/CanonicalLtd/candid/internal/identity"
	"github.com/CanonicalLtd/candid/store"
)

var NewIDPHandler = newIDPHandler

type LoginInfo loginInfo

func NewVisitCompleter(params identity.HandlerParams, store store.KeyValueStore) idp.VisitCompleter {
	return &visitCompleter{
		params:                params,
		dischargeTokenCreator: &dischargeTokenCreator{params: params},
		dischargeTokenStore:   internal.NewDischargeTokenStore(store),
		place:                 &place{params.MeetingPlace},
	}
}
