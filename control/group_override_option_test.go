/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/daedns"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

func TestParseGroupOverrideOptionWithRuntimePreservesDaeDNS(t *testing.T) {
	router := &daedns.Router{}
	src := &componentdialer.GlobalOption{
		DaeDNS:                  router,
		TransportCacheNamespace: "reload-generation-1",
	}

	dst, err := parseGroupOverrideOptionWithRuntime(config.Group{
		CheckInterval: time.Minute,
	}, config.Global{}, logrus.New(), src)
	if err != nil {
		t.Fatalf("parseGroupOverrideOptionWithRuntime() error = %v", err)
	}
	if dst == nil {
		t.Fatal("expected group override option")
	}

	if dst.DaeDNS != router {
		t.Fatal("group override dropped dae DNS router")
	}
	if dst.TransportCacheNamespace != src.TransportCacheNamespace {
		t.Fatalf("TransportCacheNamespace = %q, want %q", dst.TransportCacheNamespace, src.TransportCacheNamespace)
	}
}
