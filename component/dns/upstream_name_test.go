/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"testing"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestUpstreamByNameMatchesTheConfiguredName(t *testing.T) {
	// Upstream.String() renders the resolved URL, so the old comparison against
	// it never matched a configured name and /dns/query answered 422 for every
	// named upstream.
	sections, err := config_parser.Parse(`global {}
dns {
	upstream {
		alidns: 'udp://1.1.1.1:53'
	}
	routing {
		request {
			fallback: alidns
		}
		response {
			fallback: accept
		}
	}
}
routing {
	fallback: direct
}
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	d, err := New(&conf.Dns, &NewOption{
		Logger:                  logrus.New(),
		UpstreamResolverNetwork: "udp",
		UpstreamHostResolver: func(ctx context.Context, host, network string) (*netutils.Ip46, error, error) {
			return nil, nil, nil
		},
	})
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	if len(d.upstreamTags) != len(d.upstream) {
		t.Fatalf("upstreamTags = %v, want one tag per upstream", d.upstreamTags)
	}
	upstream, ok, err := d.UpstreamByName(context.Background(), "alidns")
	if err != nil {
		t.Fatalf("UpstreamByName: %v", err)
	}
	if !ok || upstream == nil {
		t.Fatal("a configured upstream name did not resolve")
	}
	if _, ok, _ := d.UpstreamByName(context.Background(), "missing"); ok {
		t.Fatal("an unknown name must not resolve")
	}
}
