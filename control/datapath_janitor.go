/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type bpfMaintenanceBinding struct {
	runtime   *bpfMaintenanceRuntime
	target    *ControlPlane
	previous  atomic.Pointer[ControlPlane]
	activated atomic.Bool
}

// bpfMaintenanceRuntime owns the one ringbuf reader for one BPF object set.
// Fresh object sets have distinct event maps and therefore distinct readers.
type bpfMaintenanceRuntime struct {
	bpf    *bpfObjects
	active atomic.Pointer[ControlPlane]

	lifecycleMu sync.Mutex
	startOnce   sync.Once
	started     atomic.Bool
	stopOnce    sync.Once
	stop        chan struct{}
	done        chan struct{}
	requests    chan bpfMaintenanceRequest
	workers     sync.WaitGroup

	reader     atomic.Pointer[ringbuf.Reader]
	cleanup    *bpfCleanupRuntime
	cleanupKey bpfCleanupRuntimeKey
}

// bpfCleanupRuntime serializes cleanup for one kernel ConnStateMap. Fresh BPF
// object sets use cloned handles to that map, so cleanup ownership is separate
// from event-reader ownership and transfers with process flow-state adoption.
type bpfCleanupRuntime struct {
	active      atomic.Pointer[bpfMaintenanceRuntime]
	refs        int
	cleanupMu   sync.Mutex
	scratchOnce sync.Once
	scratch     *connStateJanitorScratch
}

type bpfCleanupRuntimeKey struct {
	id       ebpf.MapID
	fallback *bpfObjects
}

type controlPlaneDatapathJanitor struct {
	fallbackMu          sync.Mutex
	fallbackScratchOnce sync.Once
	fallbackScratch     *connStateJanitorScratch
	stopOnce            sync.Once
	stop                chan struct{}
}

func (c *ControlPlane) maintenanceState() (*sync.Mutex, *connStateJanitorScratch) {
	if c.bpfMaintenance != nil && c.bpfMaintenance.runtime != nil && c.bpfMaintenance.runtime.cleanup != nil {
		return &c.bpfMaintenance.runtime.cleanup.cleanupMu, c.bpfMaintenance.runtime.cleanup.scratchBuffer()
	}
	c.fallbackScratchOnce.Do(func() {
		c.fallbackScratch = &connStateJanitorScratch{}
	})
	return &c.fallbackMu, c.fallbackScratch
}

type bpfMaintenanceRequestKind uint8

const (
	bpfMaintenanceRetirement bpfMaintenanceRequestKind = iota
	bpfMaintenanceOverflow
	bpfMaintenanceBarrier
)

type bpfMaintenanceRequest struct {
	kind          bpfMaintenanceRequestKind
	target        *ControlPlane
	staleBeforeNs uint64
	done          chan struct{}
}

var bpfMaintenanceRegistry = struct {
	sync.Mutex
	runtimes map[*bpfObjects]*bpfMaintenanceRuntime
}{runtimes: make(map[*bpfObjects]*bpfMaintenanceRuntime)}

var bpfCleanupRegistry = struct {
	sync.Mutex
	runtimes map[bpfCleanupRuntimeKey]*bpfCleanupRuntime
}{runtimes: make(map[bpfCleanupRuntimeKey]*bpfCleanupRuntime)}

func bpfCleanupKey(bpf *bpfObjects) bpfCleanupRuntimeKey {
	if bpf != nil && bpf.ConnStateMap != nil {
		if info, err := bpf.ConnStateMap.Info(); err == nil {
			if id, ok := info.ID(); ok {
				return bpfCleanupRuntimeKey{id: id}
			}
		}
	}
	return bpfCleanupRuntimeKey{fallback: bpf}
}

func acquireBpfCleanupRuntime(bpf *bpfObjects) (*bpfCleanupRuntime, bpfCleanupRuntimeKey) {
	key := bpfCleanupKey(bpf)
	bpfCleanupRegistry.Lock()
	runtime := bpfCleanupRegistry.runtimes[key]
	if runtime == nil {
		runtime = &bpfCleanupRuntime{}
		bpfCleanupRegistry.runtimes[key] = runtime
	}
	runtime.refs++
	bpfCleanupRegistry.Unlock()
	return runtime, key
}

func releaseBpfCleanupRuntime(key bpfCleanupRuntimeKey, runtime *bpfCleanupRuntime) {
	if runtime == nil {
		return
	}
	releaseState := false
	bpfCleanupRegistry.Lock()
	if current := bpfCleanupRegistry.runtimes[key]; current == runtime {
		runtime.refs--
		if runtime.refs == 0 {
			delete(bpfCleanupRegistry.runtimes, key)
			releaseState = true
		}
	}
	bpfCleanupRegistry.Unlock()
	if releaseState {
		runtime.releaseRetainedState()
	}
}

func bindBpfMaintenanceRuntime(bpf *bpfObjects, target *ControlPlane) *bpfMaintenanceBinding {
	if bpf == nil || target == nil {
		return nil
	}
	bpfMaintenanceRegistry.Lock()
	runtime := bpfMaintenanceRegistry.runtimes[bpf]
	if runtime == nil {
		cleanup, cleanupKey := acquireBpfCleanupRuntime(bpf)
		runtime = &bpfMaintenanceRuntime{
			bpf:        bpf,
			stop:       make(chan struct{}),
			done:       make(chan struct{}),
			requests:   make(chan bpfMaintenanceRequest),
			cleanup:    cleanup,
			cleanupKey: cleanupKey,
		}
		bpfMaintenanceRegistry.runtimes[bpf] = runtime
	}
	bpfMaintenanceRegistry.Unlock()
	return &bpfMaintenanceBinding{runtime: runtime, target: target}
}

func (c *ControlPlane) bpfMaintenancePredecessor() (*ControlPlane, error) {
	if c == nil || c.bpfMaintenance == nil || !c.sharedBpfReload {
		return nil, nil
	}
	c.routingEpochPeerMu.RLock()
	previous := c.routingEpochPeer
	c.routingEpochPeerMu.RUnlock()
	if previous == nil {
		return nil, fmt.Errorf("shared BPF maintenance activation has no routing epoch peer")
	}
	if previous.bpfMaintenance == nil || previous.bpfMaintenance.runtime != c.bpfMaintenance.runtime {
		return nil, fmt.Errorf("shared BPF maintenance activation does not share its peer runtime")
	}
	return previous, nil
}

func (c *ControlPlane) activateBpfMaintenance() error {
	if c == nil || c.bpfMaintenance == nil {
		return nil
	}
	previous, err := c.bpfMaintenancePredecessor()
	if err != nil {
		return err
	}
	return c.bpfMaintenance.activate(previous)
}

func (c *ControlPlane) adoptBpfMaintenanceCleanup(previous *ControlPlane) error {
	if c == nil || previous == nil {
		return fmt.Errorf("BPF maintenance cleanup adoption requires both generations")
	}
	if c.bpfMaintenance == nil && previous.bpfMaintenance == nil {
		return nil
	}
	if c.bpfMaintenance == nil || previous.bpfMaintenance == nil {
		return fmt.Errorf("BPF maintenance cleanup adoption requires both generation bindings")
	}
	successorRuntime := c.bpfMaintenance.runtime
	previousRuntime := previous.bpfMaintenance.runtime
	if successorRuntime == nil || previousRuntime == nil || successorRuntime.cleanup == nil || successorRuntime.cleanup != previousRuntime.cleanup {
		return fmt.Errorf("BPF maintenance cleanup adoption requires shared flow-state maps")
	}
	if successorRuntime == previousRuntime || successorRuntime.cleanup.active.Load() == successorRuntime {
		return nil
	}
	if !successorRuntime.cleanup.active.CompareAndSwap(previousRuntime, successorRuntime) {
		return fmt.Errorf("BPF maintenance cleanup owner changed during adoption")
	}
	return nil
}

func (b *bpfMaintenanceBinding) activate(previous *ControlPlane) error {
	if b == nil || b.runtime == nil {
		return nil
	}
	if b.runtime.active.Load() == b.target {
		b.activated.Store(true)
		if b.runtime.cleanup != nil {
			b.runtime.cleanup.active.CompareAndSwap(nil, b.runtime)
		}
		b.runtime.start()
		return nil
	}
	if !b.runtime.active.CompareAndSwap(previous, b.target) {
		return fmt.Errorf("BPF maintenance target changed during activation")
	}
	b.previous.Store(previous)
	b.activated.Store(true)
	if b.runtime.cleanup != nil {
		b.runtime.cleanup.active.CompareAndSwap(nil, b.runtime)
	}
	b.runtime.start()
	return nil
}

func (b *bpfMaintenanceBinding) deactivate() {
	if b == nil || b.runtime == nil {
		return
	}
	b.activated.Store(false)
	b.runtime.active.CompareAndSwap(b.target, nil)
}

func (b *bpfMaintenanceBinding) rollback() error {
	if b == nil || b.runtime == nil || !b.activated.CompareAndSwap(true, false) {
		return nil
	}
	previous := b.previous.Load()
	if !b.runtime.active.CompareAndSwap(b.target, previous) {
		b.activated.Store(true)
		return fmt.Errorf("BPF maintenance target changed during rollback")
	}
	return nil
}

func (r *bpfMaintenanceRuntime) start() bool {
	if r == nil {
		return false
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	select {
	case <-r.stop:
		return false
	default:
	}
	r.startOnce.Do(func() {
		r.started.Store(true)
		r.workers.Add(2)
		go func() {
			defer r.workers.Done()
			r.run()
		}()
		go func() {
			defer r.workers.Done()
			r.readEvents()
		}()
		go func() {
			r.workers.Wait()
			close(r.done)
		}()
	})
	return r.started.Load()
}

func (r *bpfMaintenanceRuntime) request(target *ControlPlane, staleBeforeNs uint64) {
	if r != nil && r.cleanup != nil {
		if owner := r.cleanup.active.Load(); owner != nil && owner != r {
			if activeTarget := owner.active.Load(); activeTarget != nil {
				target = activeTarget
			}
			owner.request(target, staleBeforeNs)
			return
		}
	}
	if !r.start() {
		return
	}
	done := make(chan struct{})
	select {
	case r.requests <- bpfMaintenanceRequest{
		kind:          bpfMaintenanceRetirement,
		target:        target,
		staleBeforeNs: staleBeforeNs,
		done:          done,
	}:
		select {
		case <-done:
		case <-r.done:
		}
	case <-r.done:
	}
}

func (r *bpfMaintenanceRuntime) requestOverflow(target *ControlPlane) {
	if r == nil || target == nil {
		return
	}
	if r.cleanup != nil {
		if owner := r.cleanup.active.Load(); owner != nil && owner != r {
			if activeTarget := owner.active.Load(); activeTarget != nil {
				target = activeTarget
			}
			owner.requestOverflow(target)
			return
		}
	}
	select {
	case r.requests <- bpfMaintenanceRequest{kind: bpfMaintenanceOverflow, target: target}:
	default:
	}
}

func (r *bpfMaintenanceRuntime) barrier() {
	if r == nil || !r.started.Load() {
		return
	}
	done := make(chan struct{})
	select {
	case r.requests <- bpfMaintenanceRequest{kind: bpfMaintenanceBarrier, done: done}:
		select {
		case <-done:
		case <-r.done:
		}
	case <-r.done:
	}
}

func stopBpfMaintenanceRuntime(bpf *bpfObjects) {
	if bpf == nil {
		return
	}
	bpfMaintenanceRegistry.Lock()
	runtime := bpfMaintenanceRegistry.runtimes[bpf]
	delete(bpfMaintenanceRegistry.runtimes, bpf)
	bpfMaintenanceRegistry.Unlock()
	if runtime == nil {
		return
	}
	runtime.stopOnce.Do(func() {
		runtime.lifecycleMu.Lock()
		close(runtime.stop)
		if reader := runtime.reader.Load(); reader != nil {
			_ = reader.Close()
		}
		started := runtime.started.Load()
		runtime.lifecycleMu.Unlock()
		if started {
			<-runtime.done
		}
		releaseBpfCleanupRuntime(runtime.cleanupKey, runtime.cleanup)
	})
}

type connStateJanitorScratch struct {
	redirectKeys   []bpfRedirectTuple
	redirectValues []bpfRedirectEntry
	redirectDelete []bpfRedirectTuple

	cookiePidKeys   []uint64
	cookiePidValues []bpfPidPname
	cookiePidDelete []uint64

	udpKeys   []bpfTuplesKey
	udpValues []bpfConnState
	udpDelete []bpfTuplesKey

	tcpDelete []bpfTuplesKey

	routingHandoffKeys   []bpfTuplesKey
	routingHandoffValues []bpfRoutingHandoffEntry
	routingHandoffDelete []bpfTuplesKey
}

func (s *connStateJanitorScratch) release() {
	if s == nil {
		return
	}
	*s = connStateJanitorScratch{}
}

func (r *bpfCleanupRuntime) scratchBuffer() *connStateJanitorScratch {
	r.scratchOnce.Do(func() {
		r.scratch = &connStateJanitorScratch{}
	})
	return r.scratch
}

func (r *bpfCleanupRuntime) releaseRetainedState() {
	if r == nil {
		return
	}
	if r.scratch != nil {
		r.scratch.release()
		r.scratch = nil
	}
}
