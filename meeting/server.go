// Copyright 2015 Canonical Ltd.

package meeting

import (
	"github.com/juju/httprequest"
	"gopkg.in/errgo.v1"
)

type handler struct {
	srv *Server
}

type waitRequest struct {
	httprequest.Route `httprequest:"GET /:Id"`
	Id                string `httprequest:",path"`
}

type waitData struct {
	Data0 []byte
	Data1 []byte
}

func (h *handler) Wait(req *waitRequest) (*waitData, error) {
	store, err := h.srv.getStore()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer store.Close()

	data0, data1, err := h.srv.localWait(req.Id, store)
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
	if err := h.srv.localDone(req.Id, req.Body.Data1); err != nil {
		return errgo.Mask(err)
	}
	return nil
}
