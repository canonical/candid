// Copyright 2014 Canonical Ltd.

package discharger

import (
	"github.com/CanonicalLtd/blues-identity/idp"
	"github.com/CanonicalLtd/blues-identity/internal/identity"
)

var NewIDPHandler = newIDPHandler

type LoginInfo loginInfo
type WaitResponse waitResponse

func NewLoginCompleter(params identity.HandlerParams) idp.LoginCompleter {
	return &loginCompleter{
		params: params,
		place:  &place{params.MeetingPlace},
	}
}
