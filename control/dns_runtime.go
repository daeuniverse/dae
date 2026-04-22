/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/dns"
	"github.com/sirupsen/logrus"
)

type controlPlaneDNSRuntime struct {
	dnsController             *DnsController
	dnsRouting                *dns.Dns
	dnsFixedDomainTtl         map[string]int
	dnsListener               *DNSListener
	dnsListenerStopRegistered bool
	delayDNSListenerStart     bool
	preparedDNSReuseHook      func() error
	preparedDNSStartHook      func() error
	dnsUpstreamsReady         chan struct{}
	dnsUpstreamAvailable      chan struct{}
	dnsUpstreamAvailableOnce  sync.Once
}

func newControlPlaneDNSRuntime(delayDNSListenerStart bool) controlPlaneDNSRuntime {
	return controlPlaneDNSRuntime{
		delayDNSListenerStart: delayDNSListenerStart,
		dnsUpstreamsReady:     make(chan struct{}),
		dnsUpstreamAvailable:  make(chan struct{}),
	}
}

func (r *controlPlaneDNSRuntime) cloneDnsCache() map[string]*DnsCache {
	if r == nil || r.dnsController == nil {
		return nil
	}
	return r.dnsController.CloneCacheForReload()
}

func (r *controlPlaneDNSRuntime) activeController(handoff *atomic.Pointer[DnsController]) *DnsController {
	if r == nil {
		return nil
	}
	if handoff != nil {
		if controller := handoff.Load(); controller != nil {
			return controller
		}
	}
	return r.dnsController
}

func (r *controlPlaneDNSRuntime) detachController() *DnsController {
	if r == nil {
		return nil
	}
	controller := r.dnsController
	r.dnsController = nil
	return controller
}

func (r *controlPlaneDNSRuntime) registerListenerStop(deferFuncs *[]func() error, stop func() error) {
	if r == nil || r.dnsListener == nil || r.dnsListenerStopRegistered {
		return
	}
	r.dnsListenerStopRegistered = true
	if deferFuncs != nil && stop != nil {
		*deferFuncs = append(*deferFuncs, stop)
	}
}

func (r *controlPlaneDNSRuntime) stopOwnedDNSListener() error {
	if r == nil || r.dnsListener == nil {
		return nil
	}
	return r.dnsListener.Stop()
}

func (r *controlPlaneDNSRuntime) closeOwnedDNSController() error {
	if r == nil || r.dnsController == nil {
		return nil
	}
	return r.dnsController.Close()
}

func (r *controlPlaneDNSRuntime) restartDNSListener(deferFuncs *[]func() error, stop func() error) error {
	if r == nil || r.dnsListener == nil {
		return nil
	}
	if err := r.dnsListener.Start(); err != nil {
		return err
	}
	r.registerListenerStop(deferFuncs, stop)
	return nil
}

func (r *controlPlaneDNSRuntime) reuseDNSListenerFrom(previous *controlPlaneDNSRuntime, owner *ControlPlane, deferFuncs *[]func() error, stop func() error) bool {
	if r == nil || previous == nil || previous.dnsListener == nil {
		return false
	}
	if r.dnsListener == nil || previous.dnsListener.endpoint != r.dnsListener.endpoint {
		return false
	}

	listener := previous.dnsListener
	previous.dnsListener = nil
	listener.SwapController(owner)
	r.dnsListener = listener
	r.delayDNSListenerStart = false
	r.registerListenerStop(deferFuncs, stop)
	return true
}

// reuseDNSControllerFrom transfers DNS runtime ownership for reload by sharing
// the previous controller's long-lived store but binding a fresh facade to the
// replacement generation. The previous generation publishes that fresh facade
// through its handoff pointer via publishHandoff, so old in-flight DNS work and
// the new generation both resolve ActiveDnsController to the same replacement
// runtime while cache and forwarder state remain shared.
func (r *controlPlaneDNSRuntime) reuseDNSControllerFrom(previous *controlPlaneDNSRuntime, option *DnsControllerOption, routing *dns.Dns, log *logrus.Logger, publishHandoff func(*DnsController)) bool {
	if r == nil || previous == nil || previous.dnsController == nil {
		return false
	}

	oldController := previous.dnsController
	if r.dnsController != nil {
		_ = r.dnsController.Close()
	}
	reusedController, err := oldController.ReuseForReload(option, routing)
	if err != nil {
		if log != nil {
			log.WithError(err).Warn("failed to reuse DNS controller for reload")
		}
		return false
	}
	if publishHandoff != nil {
		publishHandoff(reusedController)
	}
	previous.dnsController = nil
	r.dnsController = reusedController
	return true
}

func (r *controlPlaneDNSRuntime) setPreparedDNSStartHook(hook func() error) {
	if r == nil {
		return
	}
	r.preparedDNSStartHook = hook
}

func (r *controlPlaneDNSRuntime) setPreparedDNSReuseHook(hook func() error) {
	if r == nil {
		return
	}
	r.preparedDNSReuseHook = hook
}

func (r *controlPlaneDNSRuntime) waitDNSUpstreamsReady(ctx context.Context, timeout time.Duration) error {
	if r == nil || r.dnsUpstreamsReady == nil {
		return nil
	}
	if timeout <= 0 {
		select {
		case <-r.dnsUpstreamsReady:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-r.dnsUpstreamsReady:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("dns upstream warmup timed out after %v", timeout)
	}
}

func (r *controlPlaneDNSRuntime) waitDNSUpstreamAvailable(ctx context.Context, timeout time.Duration) error {
	if r == nil || r.dnsUpstreamAvailable == nil {
		return nil
	}
	if timeout <= 0 {
		select {
		case <-r.dnsUpstreamAvailable:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-r.dnsUpstreamAvailable:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("dns upstream availability timed out after %v", timeout)
	}
}

func (r *controlPlaneDNSRuntime) noteDNSUpstreamAvailable() {
	if r == nil || r.dnsUpstreamAvailable == nil {
		return
	}
	r.dnsUpstreamAvailableOnce.Do(func() {
		close(r.dnsUpstreamAvailable)
	})
}

func (r *controlPlaneDNSRuntime) startPreparedDNSListener(ctx context.Context, log *logrus.Logger, deferFuncs *[]func() error, stop func() error) error {
	if r == nil || !r.delayDNSListenerStart {
		return nil
	}
	if err := r.waitDNSUpstreamAvailable(ctx, preparedDNSWarmupTimeout); err != nil {
		if log != nil {
			log.WithError(err).Warnln("[Reload] DNS upstream availability did not finish before DNS cutover")
		}
	}
	if r.preparedDNSReuseHook != nil {
		if err := r.preparedDNSReuseHook(); err != nil {
			return err
		}
		r.preparedDNSReuseHook = nil
		if !r.delayDNSListenerStart {
			return nil
		}
	}
	if r.preparedDNSStartHook != nil {
		if err := r.preparedDNSStartHook(); err != nil {
			return err
		}
		r.preparedDNSStartHook = nil
	}
	if !r.delayDNSListenerStart {
		return nil
	}
	if err := r.restartDNSListener(deferFuncs, stop); err != nil {
		return err
	}
	r.delayDNSListenerStart = false
	return nil
}

func (r *controlPlaneDNSRuntime) releaseRetainedState() {
	if r == nil {
		return
	}
	r.dnsController = nil
	r.dnsRouting = nil
	r.dnsFixedDomainTtl = nil
	r.dnsListener = nil
	r.dnsListenerStopRegistered = false
	r.delayDNSListenerStart = false
	r.preparedDNSReuseHook = nil
	r.preparedDNSStartHook = nil
	r.dnsUpstreamsReady = nil
	r.dnsUpstreamAvailable = nil
	r.dnsUpstreamAvailableOnce = sync.Once{}
}
