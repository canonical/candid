// Copyright 2016 Canonical Ltd.

package monitoring

import (
	"time"

	"github.com/juju/httprequest"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	requestDuration = prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Namespace: "blues_identity",
		Subsystem: "handler",
		Name:      "request_duration",
		Help:      "The duration of a web request.",
	}, []string{"path_pattern"})
)

func init() {
	prometheus.MustRegister(requestDuration)
}

type Request struct {
	startTime time.Time
	params    *httprequest.Params
}

func NewRequest(p *httprequest.Params) Request {
	return Request{
		startTime: time.Now(),
		params:    p,
	}
}

func (r Request) ObserveMetric() {
	requestDuration.WithLabelValues(r.params.PathPattern).Observe(float64(time.Since(r.startTime)) / float64(time.Second))
}
