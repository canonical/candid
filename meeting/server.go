// Copyright 2015 Canonical Ltd.

package meeting

import (
	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
)

type handler struct {
	place *Place
}

type waitRequest struct {
	httprequest.Route `httprequest:"GET /:Id"`
	Id                string `httprequest:",path"`
}

type waitData struct {
	Data0 []byte
	Data1 []byte
}

func (h *handler) Wait(p httprequest.Params, req *waitRequest) (*waitData, error) {
	data0, data1, err := h.place.localWait(p.Context, req.Id)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &waitData{
		Data0: data0,
		Data1: data1,
	}, nil
}

type doneData struct {
	Data1 []byte
}

type doneRequest struct {
	httprequest.Route `httprequest:"PUT /:Id"`
	Id                string   `httprequest:",path"`
	Body              doneData `httprequest:",body"`
}

func (h *handler) Done(req *doneRequest) error {
	if err := h.place.localDone(req.Id, req.Body.Data1); err != nil {
		return errgo.Mask(err)
	}
	return nil
}
