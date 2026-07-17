/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/daedns"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
)

func TestParseGroupOverrideOptionPreservesRuntimeDialerState(t *testing.T) {
	router := &daedns.Router{}
	baseOption := &componentdialer.GlobalOption{
		DaeDNS:                  router,
		TransportCacheNamespace: "generation-1",
	}

	option, err := ParseGroupOverrideOption(config.Group{
		CheckInterval: time.Minute,
	}, config.Global{}, nil, baseOption)
	if err != nil {
		t.Fatalf("ParseGroupOverrideOption() error = %v", err)
	}
	if option == nil {
		t.Fatal("ParseGroupOverrideOption() = nil, want override option")
	}
	if option.CheckInterval != time.Minute {
		t.Fatalf("CheckInterval = %v, want %v", option.CheckInterval, time.Minute)
	}
	if option.DaeDNS != router {
		t.Fatal("DaeDNS router was not preserved from the base option")
	}
	if option.TransportCacheNamespace != baseOption.TransportCacheNamespace {
		t.Fatalf("TransportCacheNamespace = %q, want %q", option.TransportCacheNamespace, baseOption.TransportCacheNamespace)
	}
}
