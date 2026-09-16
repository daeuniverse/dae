package control

import (
	"strings"
	"testing"
)

func resetBpfMaintenanceRegistryForTest(t *testing.T) {
	t.Helper()
	bpfMaintenanceRegistry.Lock()
	runtimes := make([]*bpfMaintenanceRuntime, 0, len(bpfMaintenanceRegistry.runtimes))
	for _, runtime := range bpfMaintenanceRegistry.runtimes {
		runtimes = append(runtimes, runtime)
	}
	bpfMaintenanceRegistry.runtimes = make(map[*bpfObjects]*bpfMaintenanceRuntime)
	bpfMaintenanceRegistry.Unlock()
	for _, runtime := range runtimes {
		runtime.stopOnce.Do(func() {
			close(runtime.stop)
			if reader := runtime.reader.Load(); reader != nil {
				_ = reader.Close()
			}
			if runtime.started.Load() {
				<-runtime.done
			}
			releaseBpfCleanupRuntime(runtime.cleanupKey, runtime.cleanup)
		})
	}
	bpfCleanupRegistry.Lock()
	remainingCleanupRuntimes := len(bpfCleanupRegistry.runtimes)
	bpfCleanupRegistry.Unlock()
	if remainingCleanupRuntimes != 0 {
		t.Fatalf("%d BPF cleanup runtimes remained registered", remainingCleanupRuntimes)
	}
}

func TestBpfMaintenanceRuntimeSharedByBpfObject(t *testing.T) {
	resetBpfMaintenanceRegistryForTest(t)
	defer resetBpfMaintenanceRegistryForTest(t)

	bpf := &bpfObjects{}
	first := &ControlPlane{}
	second := &ControlPlane{}
	firstBinding := bindBpfMaintenanceRuntime(bpf, first)
	secondBinding := bindBpfMaintenanceRuntime(bpf, second)

	if firstBinding.runtime != secondBinding.runtime {
		t.Fatal("bindings for one bpfObjects did not share a runtime")
	}
	other := bindBpfMaintenanceRuntime(&bpfObjects{}, &ControlPlane{})
	if other.runtime == firstBinding.runtime {
		t.Fatal("pointer-distinct bpfObjects shared a runtime")
	}
}

func TestBpfMaintenanceRuntimeDispatchTransitions(t *testing.T) {
	resetBpfMaintenanceRegistryForTest(t)
	defer resetBpfMaintenanceRegistryForTest(t)

	bpf := &bpfObjects{}
	oldPlane := &ControlPlane{}
	newPlane := &ControlPlane{}
	oldBinding := bindBpfMaintenanceRuntime(bpf, oldPlane)
	newBinding := bindBpfMaintenanceRuntime(bpf, newPlane)

	if err := oldBinding.activate(nil); err != nil {
		t.Fatalf("activate old: %v", err)
	}
	if got := oldBinding.runtime.active.Load(); got != oldPlane {
		t.Fatalf("active target = %p, want old %p", got, oldPlane)
	}
	if err := newBinding.activate(oldPlane); err != nil {
		t.Fatalf("activate new: %v", err)
	}
	if got := oldBinding.runtime.active.Load(); got != newPlane {
		t.Fatalf("active target = %p, want new %p", got, newPlane)
	}
	if err := newBinding.rollback(); err != nil {
		t.Fatalf("rollback new: %v", err)
	}
	if got := oldBinding.runtime.active.Load(); got != oldPlane {
		t.Fatalf("active target = %p, want restored old %p", got, oldPlane)
	}
}

func TestBpfMaintenanceRuntimeStaleRollbackDoesNotClobberTarget(t *testing.T) {
	resetBpfMaintenanceRegistryForTest(t)
	defer resetBpfMaintenanceRegistryForTest(t)

	bpf := &bpfObjects{}
	oldPlane := &ControlPlane{}
	newPlane := &ControlPlane{}
	laterPlane := &ControlPlane{}
	oldBinding := bindBpfMaintenanceRuntime(bpf, oldPlane)
	newBinding := bindBpfMaintenanceRuntime(bpf, newPlane)
	laterBinding := bindBpfMaintenanceRuntime(bpf, laterPlane)

	if err := oldBinding.activate(nil); err != nil {
		t.Fatal(err)
	}
	if err := newBinding.activate(oldPlane); err != nil {
		t.Fatal(err)
	}
	if err := laterBinding.activate(newPlane); err != nil {
		t.Fatal(err)
	}
	if err := newBinding.rollback(); err == nil || !strings.Contains(err.Error(), "changed during rollback") {
		t.Fatalf("stale rollback error = %v", err)
	}
	if got := oldBinding.runtime.active.Load(); got != laterPlane {
		t.Fatalf("stale rollback clobbered later target: got %p want %p", got, laterPlane)
	}
}

func TestBpfMaintenanceCleanupFollowsFreshMapHandleAdoption(t *testing.T) {
	resetBpfMaintenanceRegistryForTest(t)
	defer resetBpfMaintenanceRegistryForTest(t)

	connState := newJanitorTestMap(t, "conn_state_map")
	clonedConnState, err := connState.Clone()
	if err != nil {
		t.Fatalf("clone conn-state map: %v", err)
	}
	t.Cleanup(func() {
		if err := clonedConnState.Close(); err != nil {
			t.Errorf("close cloned conn-state map: %v", err)
		}
	})

	previous := &ControlPlane{}
	successor := &ControlPlane{}
	previous.bpfMaintenance = bindBpfMaintenanceRuntime(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: connState}}, previous)
	successor.bpfMaintenance = bindBpfMaintenanceRuntime(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: clonedConnState}}, successor)
	if previous.bpfMaintenance.runtime == successor.bpfMaintenance.runtime {
		t.Fatal("pointer-distinct BPF object sets shared an event runtime")
	}
	if previous.bpfMaintenance.runtime.cleanup != successor.bpfMaintenance.runtime.cleanup {
		t.Fatal("cloned conn-state handles did not share a cleanup runtime")
	}
	if err := previous.bpfMaintenance.activate(nil); err != nil {
		t.Fatalf("activate previous runtime: %v", err)
	}
	if err := successor.bpfMaintenance.activate(nil); err != nil {
		t.Fatalf("activate successor event runtime: %v", err)
	}
	cleanup := previous.bpfMaintenance.runtime.cleanup
	if got := cleanup.active.Load(); got != previous.bpfMaintenance.runtime {
		t.Fatalf("cleanup owner = %p, want previous %p", got, previous.bpfMaintenance.runtime)
	}
	if err := successor.adoptBpfMaintenanceCleanup(previous); err != nil {
		t.Fatalf("adopt successor cleanup: %v", err)
	}
	if got := cleanup.active.Load(); got != successor.bpfMaintenance.runtime {
		t.Fatalf("cleanup owner = %p, want successor %p", got, successor.bpfMaintenance.runtime)
	}
	if err := previous.adoptBpfMaintenanceCleanup(successor); err != nil {
		t.Fatalf("restore previous cleanup: %v", err)
	}
	if got := cleanup.active.Load(); got != previous.bpfMaintenance.runtime {
		t.Fatalf("restored cleanup owner = %p, want previous %p", got, previous.bpfMaintenance.runtime)
	}
}

func TestProcessFlowAdoptionRollsBackOnStaleCleanupOwner(t *testing.T) {
	resetBpfMaintenanceRegistryForTest(t)
	defer resetBpfMaintenanceRegistryForTest(t)

	connState := newJanitorTestMap(t, "conn_state_map")
	clonedConnState, err := connState.Clone()
	if err != nil {
		t.Fatalf("clone conn-state map: %v", err)
	}
	t.Cleanup(func() {
		if err := clonedConnState.Close(); err != nil {
			t.Errorf("close cloned conn-state map: %v", err)
		}
	})
	previousBpf := &bpfObjects{bpfMaps: bpfMaps{ConnStateMap: connState}}
	successorBpf := &bpfObjects{bpfMaps: bpfMaps{ConnStateMap: clonedConnState}}
	manager := NewSessionManager(t.Context())
	t.Cleanup(func() { _ = manager.Close() })
	manager.udpBPF.Store(previousBpf)
	previous := &ControlPlane{sessionManager: manager, core: &controlPlaneCore{}}
	previous.core.bpf.Store(previousBpf)
	successor := &ControlPlane{sessionManager: manager, core: &controlPlaneCore{}}
	successor.core.bpf.Store(successorBpf)
	previous.bpfMaintenance = bindBpfMaintenanceRuntime(previousBpf, previous)
	successor.bpfMaintenance = bindBpfMaintenanceRuntime(successorBpf, successor)
	if err := previous.bpfMaintenance.activate(nil); err != nil {
		t.Fatalf("activate previous runtime: %v", err)
	}
	if err := successor.bpfMaintenance.activate(nil); err != nil {
		t.Fatalf("activate successor event runtime: %v", err)
	}
	previous.bpfMaintenance.runtime.cleanup.active.Store(&bpfMaintenanceRuntime{})

	if err := successor.AdoptProcessFlowDatapath(previous); err == nil {
		t.Fatal("flow adoption succeeded with a stale cleanup owner")
	}
	if got := manager.udpBPF.Load(); got != previousBpf {
		t.Fatalf("UDP flow owner = %p after rollback, want previous %p", got, previousBpf)
	}
}

func TestBpfMaintenanceRuntimeRejectsStaleActivation(t *testing.T) {
	resetBpfMaintenanceRegistryForTest(t)
	defer resetBpfMaintenanceRegistryForTest(t)

	bpf := &bpfObjects{}
	previous := &ControlPlane{}
	candidate := &ControlPlane{sharedBpfReload: true}
	later := &ControlPlane{}
	previous.bpfMaintenance = bindBpfMaintenanceRuntime(bpf, previous)
	candidate.bpfMaintenance = bindBpfMaintenanceRuntime(bpf, candidate)
	candidate.routingEpochPeer = previous
	candidate.bpfMaintenance.runtime.active.Store(later)

	if err := candidate.activateBpfMaintenance(); err == nil {
		t.Fatal("stale candidate replaced a later maintenance target")
	}
	if got := candidate.bpfMaintenance.runtime.active.Load(); got != later {
		t.Fatalf("stale activation changed target to %p, want %p", got, later)
	}
	if err := candidate.bpfMaintenance.rollback(); err != nil {
		t.Fatalf("rollback after rejected activation should be a no-op: %v", err)
	}
}

func TestStopBpfMaintenanceRuntimeJoinsActors(t *testing.T) {
	resetBpfMaintenanceRegistryForTest(t)
	defer resetBpfMaintenanceRegistryForTest(t)

	bpf := &bpfObjects{}
	binding := bindBpfMaintenanceRuntime(bpf, &ControlPlane{})
	if err := binding.activate(nil); err != nil {
		t.Fatal(err)
	}
	stopBpfMaintenanceRuntime(bpf)
	select {
	case <-binding.runtime.done:
	default:
		t.Fatal("stop returned before maintenance actors joined")
	}

	bpfMaintenanceRegistry.Lock()
	_, exists := bpfMaintenanceRegistry.runtimes[bpf]
	bpfMaintenanceRegistry.Unlock()
	if exists {
		t.Fatal("stopped runtime remained registered")
	}
}
