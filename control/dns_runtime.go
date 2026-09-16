/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
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
	dnsController     *DnsController
	dnsRouting        *dns.Dns
	dnsFixedDomainTtl map[string]int
	// The config-derived controller tunables are retained here so that every
	// dnsControllerOption() caller — the initial build, reload reuse, and the
	// staged handoff — assembles the same behaviour. Patching them onto the
	// option at one call site silently resets them to zero at the others,
	// which turned the cache size limit off after a reload.
	dnsOptimisticCache         bool
	dnsOptimisticCacheTtl      int
	dnsOptimisticStaleReplyTtl int
	dnsMaxCacheSize            int
	dnsIpVersionPrefer         int

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
	replacementController := r.dnsController
	reusedController, err := oldController.ReuseForReload(option, routing)
	if err != nil {
		if log != nil {
			log.WithError(err).Warn("failed to reuse DNS controller for reload")
		}
		return false
	}
	if replacementController != nil && replacementController != oldController {
		_ = replacementController.Close()
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

func (r *controlPlaneDNSRuntime) startPreparedDNSListener(ctx context.Context, deferFuncs *[]func() error, stop func() error) error {
	return r.startPreparedDNSListenerWithWarmupTimeout(ctx, deferFuncs, stop, preparedDNSWarmupTimeout)
}

func (r *controlPlaneDNSRuntime) startPreparedDNSListenerWithWarmupTimeout(ctx context.Context, deferFuncs *[]func() error, stop func() error, warmupTimeout time.Duration) error {
	if r == nil || !r.delayDNSListenerStart {
		return nil
	}
	if err := r.waitDNSUpstreamAvailable(ctx, warmupTimeout); err != nil {
		return fmt.Errorf("wait for DNS upstream availability before prepared cutover: %w", err)
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

// RestorePreparedDNSRuntimeForRollback returns DNS resources transferred to a
// prepared candidate back to the still-active previous generation.
func (c *ControlPlane) RestorePreparedDNSRuntimeForRollback(
	previous *ControlPlane,
	restoreController bool,
	restoreListener bool,
) (listenerRestoredActive bool, err error) {
	if c == nil || previous == nil {
		return false, fmt.Errorf("restore prepared DNS runtime: both control planes are required")
	}
	activeControlPlanePublication.mu.Lock()
	defer activeControlPlanePublication.mu.Unlock()

	if restoreController {
		if c.dnsController == nil {
			return false, fmt.Errorf("restore prepared DNS runtime: candidate controller is unavailable")
		}
		if previous.dnsController != nil {
			return false, fmt.Errorf("restore prepared DNS runtime: previous controller still owns a controller")
		}
	}
	if restoreListener {
		if c.dnsListener == nil {
			return false, fmt.Errorf("restore prepared DNS runtime: candidate listener is unavailable")
		}
		if previous.dnsListener != nil {
			return false, fmt.Errorf("restore prepared DNS runtime: previous listener still owns a listener")
		}
	}

	if restoreController {
		transferred := c.dnsController
		restored, restoreErr := transferred.ReuseForReload(previous.dnsControllerOption(), previous.dnsRouting)
		if restoreErr != nil {
			return false, fmt.Errorf("restore prepared DNS controller: %w", restoreErr)
		}
		if restored == nil {
			return false, fmt.Errorf("restore prepared DNS controller: restored controller is nil")
		}
		c.dnsController = nil
		previous.dnsController = restored
		previous.clearDNSHandoffControllerIfMatch(transferred)
	}

	if restoreListener {
		listener := c.dnsListener
		c.dnsListener = nil
		c.dnsListenerStopRegistered = false
		previous.dnsListener = listener
		listener.SwapController(previous)
		listenerRestoredActive = true
	}

	return listenerRestoredActive, nil
}
