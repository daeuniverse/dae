/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	descNamePattern   = regexp.MustCompile(`fqName: "([^"]+)"`)
	descLabelsPattern = regexp.MustCompile(`variableLabels: \{([^}]*)\}`)
)

// descriptorLabels maps each descriptor name to its variable label names.
func descriptorLabels(collector prometheus.Collector) map[string][]string {
	ch := make(chan *prometheus.Desc, 64)
	collector.Describe(ch)
	close(ch)

	labels := make(map[string][]string)
	for desc := range ch {
		s := desc.String()
		name := descNamePattern.FindStringSubmatch(s)
		vars := descLabelsPattern.FindStringSubmatch(s)
		if len(name) != 2 || len(vars) != 2 {
			continue
		}
		if vars[1] == "" {
			labels[name[1]] = nil
		} else {
			labels[name[1]] = strings.Split(vars[1], ",")
		}
	}
	return labels
}

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

func requireNoDescriptor(t *testing.T, names map[string]struct{}, name string) {
	t.Helper()
	if _, ok := names[name]; ok {
		t.Fatalf("unexpected descriptor %q", name)
	}
}

func requireDescriptors(t *testing.T, names map[string]struct{}, expected []string) {
	t.Helper()
	for _, name := range expected {
		requireDescriptor(t, names, name)
	}
}

func TestDnsCollectorDescribeIncludesPhase2Descriptors(t *testing.T) {
	names := descriptorNames(NewDnsCollector(nil))
	requireDescriptors(t, names, []string{
		"dae_dns_cache_entries",
		"dae_dns_concurrency_in_use",
		"dae_dns_forwarder_cache_entries",
		"dae_dns_forwarder_in_flight",
		"dae_dns_query_total",
		"dae_dns_cache_hit_total",
		"dae_dns_cache_lazy_hit_total",
		"dae_dns_upstream_query_total",
		"dae_dns_upstream_err_total",
		"dae_dns_rejected_total",
		"dae_dns_refused_total",
		"dae_dns_response_latency_seconds",
		"dae_dns_upstream_latency_seconds",
	})
	requireNoDescriptor(t, names, "dae_dns_concurrency_limit")
	requireNoDescriptor(t, names, "dae_dns_cache_miss_total")
}

func TestDialerCollectorDescribeIncludesPhase2Descriptors(t *testing.T) {
	names := descriptorNames(NewDialerCollector(nil))
	requireDescriptors(t, names, []string{
		"dae_dialer_alive",
		"dae_dialer_latency_last_seconds",
		"dae_dialer_latency_avg10_seconds",
		"dae_dialer_latency_moving_avg_seconds",
		"dae_health_check_total",
		"dae_health_check_failure_total",
		"dae_group_alive_dialers_total",
	})
}

func TestConnCollectorDescribeIncludesPhase2Descriptors(t *testing.T) {
	names := descriptorNames(NewConnCollector(nil))
	requireDescriptors(t, names, []string{
		"dae_tcp_connections_active",
		"dae_udp_endpoints_active",
		"dae_udp_task_queues_active",
		"dae_tcp_connections_total",
		"dae_udp_connections_total",
	})
}

func TestRuntimeCollectorDescribeIncludesRuntimeDescriptors(t *testing.T) {
	names := descriptorNames(NewRuntimeCollector(nil))
	requireDescriptors(t, names, []string{
		"dae_runtime_upload_bytes_total",
		"dae_runtime_download_bytes_total",
		"dae_runtime_upload_rate_bytes_per_second",
		"dae_runtime_download_rate_bytes_per_second",
	})
	// The node metrics exported the share link, which carries credentials.
	requireNoDescriptor(t, names, "dae_node_latency_seconds")
	requireNoDescriptor(t, names, "dae_node_alive")
}

// TestNoDescriptorExportsLinkLabel guards against exporting node share links:
// they embed proxy passwords and UUIDs.
func TestNoDescriptorExportsLinkLabel(t *testing.T) {
	collectors := map[string]prometheus.Collector{
		"dns":     NewDnsCollector(nil),
		"dialer":  NewDialerCollector(nil),
		"conn":    NewConnCollector(nil),
		"runtime": NewRuntimeCollector(nil),
	}
	for collectorName, collector := range collectors {
		labels := descriptorLabels(collector)
		if len(labels) == 0 {
			t.Fatalf("%s collector: no descriptor labels parsed; descriptorLabels is out of date", collectorName)
		}
		for desc, names := range labels {
			if slices.Contains(names, "link") {
				t.Fatalf("%s collector: %s exports a link label", collectorName, desc)
			}
		}
	}
	// Keep the check non-vacuous: a labelled descriptor must parse.
	if got := descriptorLabels(NewDialerCollector(nil))["dae_dialer_alive"]; !slices.Equal(got, []string{"group", "dialer", "network"}) {
		t.Fatalf("dae_dialer_alive labels = %v", got)
	}
}
