/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import "github.com/prometheus/client_golang/prometheus"

func NewRegistry(state *State) *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
		prometheus.NewGoCollector(),
		NewDialerCollector(state),
		NewDnsCollector(state),
		NewConnCollector(state),
	)
	return reg
}
