// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package discharger

import (
	"github.com/CanonicalLtd/candid/idp"
	"github.com/CanonicalLtd/candid/internal/identity"
)

var NewIDPHandler = newIDPHandler

type LoginInfo loginInfo

func NewVisitCompleter(params identity.HandlerParams) idp.VisitCompleter {
	return &visitCompleter{
		params:                params,
		dischargeTokenCreator: &dischargeTokenCreator{params: params},
		place:                 &place{params.MeetingPlace},
	}
}
