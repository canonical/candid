// Copyright 2018 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package monitoring

import (
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"

	"github.com/CanonicalLtd/candid/store"
)

var logger = loggo.GetLogger("candid.internal.monitoring")

type StoreCollector struct {
	Store store.Store
}

var storeIdentiesDesc = prometheus.NewDesc(
	"candid_store_identities",
	"Number of stored identities",
	[]string{"provider"},
	nil,
)

// Describe implements prometheus.Collector
func (c StoreCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- storeIdentiesDesc
}

// Describe implements prometheus.Collector
func (c StoreCollector) Collect(ch chan<- prometheus.Metric) {
	counts, err := c.Store.IdentityCounts(context.Background())
	if err != nil {
		logger.Infof("error collecting metrics: %s", err)
		return
	}
	for provider, count := range counts {
		ch <- prometheus.MustNewConstMetric(storeIdentiesDesc, prometheus.GaugeValue, float64(count), provider)
	}
}
