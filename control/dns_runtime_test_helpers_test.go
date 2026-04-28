/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync"
)

func newTestDnsControllerStore() *dnsControllerStore {
	return &dnsControllerStore{
		dnsCache:          sync.Map{},
		dnsForwarderCache: sync.Map{},
		prefWaitRegistry:  newPreferenceWaitRegistry(),
	}
}

func newTestDnsController() *DnsController {
	return &DnsController{
		dnsControllerStore: newTestDnsControllerStore(),
	}
}

func setTestDnsControllerRuntime(ctrl *DnsController, apply func(*dnsControllerRuntimeState)) *DnsController {
	if ctrl == nil {
		ctrl = newTestDnsController()
	}
	if ctrl.dnsControllerStore == nil {
		ctrl.dnsControllerStore = newTestDnsControllerStore()
	}
	rt := dnsControllerRuntimeState{
		lifecycleCtx: context.Background(),
	}
	if current := ctrl.runtimeState.Load(); current != nil {
		rt = *current
		if rt.lifecycleCtx == nil {
			rt.lifecycleCtx = context.Background()
		}
	}
	apply(&rt)
	if rt.lifecycleCtx == nil {
		rt.lifecycleCtx = context.Background()
	}
	ctrl.runtimeState.Store(&rt)
	return ctrl
}
