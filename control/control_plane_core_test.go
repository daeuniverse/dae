package control

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
)

func TestControlPlaneCore_Flip_Race(t *testing.T) {
	// coreFlip is global in package control.
	// Reset it to 0 for deterministic test.
	atomic.StoreInt32(&coreFlip, 0)

	// Since Flip() doesn't access any struct fields, we can use an empty struct.
	c := &controlPlaneCore{}

	var wg sync.WaitGroup
	iterations := 1000 // Must be even

	for range iterations {
		wg.Go(func() {
			c.Flip()
		})
	}

	wg.Wait()

	val := atomic.LoadInt32(&coreFlip)
	// If atomic operations are correct, flipping 0 an even number of times should result in 0.
	// If a race occurred (e.g. lost update), the result might be 1.
	if val != 0 {
		t.Errorf("Expected coreFlip to be 0 after %d flips, got %d. Race condition detected.", iterations, val)
	}
}

func TestControlPlaneCore_EjectBpfKeepsHookCleanupForClose(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	core := newControlPlaneCore(logger, nil, nil, nil, false)
	calls := 0
	core.addManagedBpfHookCleanup(func() error {
		calls++
		return nil
	})

	core.EjectBpf()
	if core.bpfOwned {
		t.Fatal("expected EjectBpf to transfer BPF ownership")
	}

	if err := core.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
	if calls != 1 {
		t.Fatalf("expected hook cleanup to run once after EjectBpf, got %d", calls)
	}
}

func TestControlPlaneCore_InjectBpfClaimsOwnershipForReloadGeneration(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	core := newControlPlaneCore(logger, nil, nil, nil, true)
	if core.bpfOwned {
		t.Fatal("expected reload generation to start without BPF ownership")
	}

	core.InjectBpf(nil)

	if !core.bpfOwned {
		t.Fatal("expected InjectBpf to claim BPF ownership")
	}
	if core.bpfEjected {
		t.Fatal("expected InjectBpf to clear the ejected state")
	}
}

func TestControlPlaneCore_InheritLpmIndicesSkipsReusedSlots(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	core := newControlPlaneCore(logger, nil, nil, nil, true)
	core.lpmTrieIndices = []uint32{4, 5}

	core.InheritLpmIndices([]uint32{1, 4, 7})

	got := make(map[uint32]struct{}, len(core.lpmTrieIndices))
	for _, idx := range core.lpmTrieIndices {
		got[idx] = struct{}{}
	}

	for _, want := range []uint32{1, 4, 5, 7} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected inherited index set to contain %d, got %#v", want, core.lpmTrieIndices)
		}
	}
	if len(got) != 4 {
		t.Fatalf("expected no duplicate inherited indices, got %#v", core.lpmTrieIndices)
	}
}

func TestControlPlaneCore_EjectLpmIndicesTransfersOwnership(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	core := newControlPlaneCore(logger, nil, nil, nil, false)
	core.lpmTrieIndices = []uint32{2, 3, 5}

	indices := core.EjectLpmIndices()

	if len(core.lpmTrieIndices) != 0 {
		t.Fatalf("expected core LPM indices to be cleared after ejection, got %#v", core.lpmTrieIndices)
	}
	if len(indices) != 3 {
		t.Fatalf("expected 3 ejected LPM indices, got %#v", indices)
	}
}

func TestControlPlaneCore_ReplaceLpmIndicesReplacesTrackedSet(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	core := newControlPlaneCore(logger, nil, nil, nil, false)
	core.lpmTrieIndices = []uint32{2, 3, 5}

	core.ReplaceLpmIndices([]uint32{7, 11})

	if got := core.lpmTrieIndices; len(got) != 2 || got[0] != 7 || got[1] != 11 {
		t.Fatalf("expected replaced LPM indices [7 11], got %#v", got)
	}
}

type fakeCgroupAttachment struct {
	closeCalls atomic.Int32
}

func (f *fakeCgroupAttachment) Close() error {
	f.closeCalls.Add(1)
	return nil
}

func TestControlPlaneCore_SetupSkPidMonitorRollsBackPartialAttach(t *testing.T) {
	oldDetect := detectCgroupPathFunc
	oldAttach := attachCgroupFunc
	detectCgroupPathFunc = func() (string, error) { return "/sys/fs/cgroup", nil }
	var attachments []*fakeCgroupAttachment
	attachCgroupFunc = func(ciliumLink.CgroupOptions) (cgroupAttachment, error) {
		attachment := &fakeCgroupAttachment{}
		attachments = append(attachments, attachment)
		if len(attachments) == 3 {
			return nil, fmt.Errorf("boom")
		}
		return attachment, nil
	}
	defer func() {
		detectCgroupPathFunc = oldDetect
		attachCgroupFunc = oldAttach
	}()

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	core := newControlPlaneCore(logger, &bpfObjects{
		bpfPrograms: bpfPrograms{
			TproxyWanCgSockCreate:  &ebpf.Program{},
			TproxyWanCgSockRelease: &ebpf.Program{},
			TproxyWanCgConnect4:    &ebpf.Program{},
			TproxyWanCgConnect6:    &ebpf.Program{},
			TproxyWanCgSendmsg4:    &ebpf.Program{},
			TproxyWanCgSendmsg6:    &ebpf.Program{},
		},
	}, nil, nil, false)

	if err := core.setupSkPidMonitor(); err == nil {
		t.Fatal("setupSkPidMonitor() error = nil, want failure")
	}
	if got := len(core.bpfHookDetachFuncs); got != 0 {
		t.Fatalf("len(bpfHookDetachFuncs) = %d, want 0 after rollback", got)
	}
	if got := attachments[0].closeCalls.Load(); got != 1 {
		t.Fatalf("first attachment Close() calls = %d, want 1", got)
	}
	if got := attachments[1].closeCalls.Load(); got != 1 {
		t.Fatalf("second attachment Close() calls = %d, want 1", got)
	}
}
