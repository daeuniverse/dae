/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import (
	"regexp"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

var descNamePattern = regexp.MustCompile(`fqName: "([^"]+)"`)

func descriptorNames(collector prometheus.Collector) map[string]struct{} {
	ch := make(chan *prometheus.Desc, 64)
	collector.Describe(ch)
	close(ch)

	names := make(map[string]struct{})
	for desc := range ch {
		matches := descNamePattern.FindStringSubmatch(desc.String())
		if len(matches) == 2 {
			names[matches[1]] = struct{}{}
		}
	}
	return names
}

func requireDescriptor(t *testing.T, names map[string]struct{}, name string) {
	t.Helper()
	if _, ok := names[name]; !ok {
		t.Fatalf("missing descriptor %q", name)
	}
}

func TestDnsCollectorDescribeIncludesPhase2Descriptors(t *testing.T) {
	names := descriptorNames(NewDnsCollector(nil))
	requireDescriptor(t, names, "dae_dns_query_total")
	requireDescriptor(t, names, "dae_dns_cache_hit_total")
	requireDescriptor(t, names, "dae_dns_cache_lazy_hit_total")
	requireDescriptor(t, names, "dae_dns_cache_miss_total")
	requireDescriptor(t, names, "dae_dns_upstream_query_total")
	requireDescriptor(t, names, "dae_dns_upstream_err_total")
	requireDescriptor(t, names, "dae_dns_rejected_total")
	requireDescriptor(t, names, "dae_dns_refused_total")
	requireDescriptor(t, names, "dae_dns_response_latency_seconds")
	requireDescriptor(t, names, "dae_dns_upstream_latency_seconds")
}

func TestDialerCollectorDescribeIncludesPhase2Descriptors(t *testing.T) {
	names := descriptorNames(NewDialerCollector(nil))
	requireDescriptor(t, names, "dae_health_check_total")
	requireDescriptor(t, names, "dae_health_check_failure_total")
}

func TestConnCollectorDescribeIncludesPhase2Descriptors(t *testing.T) {
	names := descriptorNames(NewConnCollector(nil))
	requireDescriptor(t, names, "dae_tcp_connections_total")
	requireDescriptor(t, names, "dae_udp_connections_total")
}
