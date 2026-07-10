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
	"github.com/vishvananda/netlink"
)

// mkLink returns a minimal netlink.Link (a *netlink.Dummy) without touching the
// real kernel. Dummy implements the Link interface and its Attrs().Name is what
// our mocked filterLister keys on.
func mkLink(name string) netlink.Link {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

// mkFilters wraps a single handle (major<<16) into a netlink.Filter list.
func mkFilters(major uint16) []netlink.Filter {
	return []netlink.Filter{
		&netlink.GenericFilter{FilterAttrs: netlink.FilterAttrs{Handle: uint32(major) << 16}},
	}
}

func TestValidateDatapathBindings(t *testing.T) {
	// Swap out the kernel-touching helpers for mocks.
	origLinkByName := linkByName
	origFilterLister := filterLister
	t.Cleanup(func() {
		linkByName = origLinkByName
		filterLister = origFilterLister
	})

	dae0 := mkLink("dae0")
	eth0 := mkLink("eth0")
	eth1 := mkLink("eth1")

	// boundIfaces mimics what bindDaens/_bindLan/_bindWan record after a
	// successful bind: the *resolved* interface name plus the expected handle.
	// A configured "auto" LAN/WAN is expanded to the real NIC here, and dae0 is
	// only present when bindDaens actually created it — which is exactly why the
	// production validation no longer hard-codes dae0 or the raw "auto" name.
	tests := []struct {
		name         string
		known        map[string]netlink.Link
		filters      map[string][]netlink.Filter
		bound        []boundIface
		wantEmpty    bool
		wantContains []string
	}{
		{
			name:      "all bindings present",
			known:     map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters:   map[string][]netlink.Filter{"dae0": mkFilters(0x2022), "eth0": mkFilters(0x2023)},
			bound:     []boundIface{{"dae0", "dae0", 0x2022}, {"eth0", "LAN", 0x2023}},
			wantEmpty: true,
		},
		{
			name:         "dae0 filter missing",
			known:        map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters:      map[string][]netlink.Filter{"eth0": mkFilters(0x2023)},
			bound:        []boundIface{{"dae0", "dae0", 0x2022}, {"eth0", "LAN", 0x2023}},
			wantEmpty:    false,
			wantContains: []string{"dae0 (dae0, handle 0x2022 missing)"},
		},
		{
			name:         "lan filter missing",
			known:        map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters:      map[string][]netlink.Filter{"dae0": mkFilters(0x2022)},
			bound:        []boundIface{{"dae0", "dae0", 0x2022}, {"eth0", "LAN", 0x2023}},
			wantEmpty:    false,
			wantContains: []string{"eth0 (LAN, handle 0x2023 missing)"},
		},
		{
			name:         "wan filter missing",
			known:        map[string]netlink.Link{"dae0": dae0, "eth1": eth1},
			filters:      map[string][]netlink.Filter{"dae0": mkFilters(0x2022)},
			bound:        []boundIface{{"dae0", "dae0", 0x2022}, {"eth1", "WAN", 0x2023}},
			wantEmpty:    false,
			wantContains: []string{"eth1 (WAN, handle 0x2023 missing)"},
		},
		{
			name:         "interface not found",
			known:        map[string]netlink.Link{"dae0": dae0},
			filters:      map[string][]netlink.Filter{"dae0": mkFilters(0x2022)},
			bound:        []boundIface{{"dae0", "dae0", 0x2022}, {"eth0", "LAN", 0x2023}},
			wantEmpty:    false,
			wantContains: []string{"eth0 (LAN, link not found)"},
		},
		{
			name:      "auto-resolved lan (resolved name only)",
			known:     map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters:   map[string][]netlink.Filter{"dae0": mkFilters(0x2022), "eth0": mkFilters(0x2023)},
			bound:     []boundIface{{"dae0", "dae0", 0x2022}, {"eth0", "LAN", 0x2023}},
			wantEmpty: true,
		},
		{
			name:      "no bindings recorded (e.g. unit test without a real bind)",
			known:     map[string]netlink.Link{},
			filters:   map[string][]netlink.Filter{},
			bound:     nil,
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			linkByName = func(name string) (netlink.Link, error) {
				if l, ok := tt.known[name]; ok {
					return l, nil
				}
				return nil, fmt.Errorf("link %s not found", name)
			}
			filterLister = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
				if fs, ok := tt.filters[link.Attrs().Name]; ok {
					return fs, nil
				}
				return nil, nil
			}

			c := &controlPlaneCore{datapathIfaces: tt.bound}
			missing, _ := c.validateDatapathBindings()

			if tt.wantEmpty {
				if len(missing) != 0 {
					t.Fatalf("expected no missing bindings, got %v", missing)
				}
				return
			}
			if len(missing) == 0 {
				t.Fatalf("expected missing bindings %v, got none", tt.wantContains)
			}
			for _, want := range tt.wantContains {
				found := false
				for _, m := range missing {
					if m == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing binding %q not found in %v", want, missing)
				}
			}
		})
	}
}

func TestRepairDatapathBindings(t *testing.T) {
	origLinkByName := linkByName
	origFilterLister := filterLister
	origRebindLan := rebindLanFn
	origRebindWan := rebindWanFn
	t.Cleanup(func() {
		linkByName = origLinkByName
		filterLister = origFilterLister
		rebindLanFn = origRebindLan
		rebindWanFn = origRebindWan
	})

	dae0 := mkLink("dae0")
	eth0 := mkLink("eth0")
	eth1 := mkLink("eth1")

	tests := []struct {
		name string
		// initial state
		known map[string]netlink.Link
		// lanRebindFixes / wanRebindFixes: a successful rebind "adds" the
		// missing filter to the mock, simulating a real re-attach.
		filters          map[string][]netlink.Filter
		bound            []boundIface
		lanRebindErr     error
		wanRebindErr     error
		lanRebindFixes   bool
		wanRebindFixes   bool
		wantStillMissing []string
		wantFatal        bool
	}{
		{
			name:             "LAN missing then self-healed",
			known:            map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters:          map[string][]netlink.Filter{"dae0": mkFilters(0x2022)},
			bound:            []boundIface{{"dae0", "dae0", 0x2022}, {"eth0", "LAN", 0x2023}},
			lanRebindFixes:   true,
			wantStillMissing: nil,
			wantFatal:        false,
		},
		{
			name:             "WAN missing but rebind fails (warn only)",
			known:            map[string]netlink.Link{"dae0": dae0, "eth1": eth1},
			filters:          map[string][]netlink.Filter{"dae0": mkFilters(0x2022)},
			bound:            []boundIface{{"dae0", "dae0", 0x2022}, {"eth1", "WAN", 0x2023}},
			wanRebindErr:     fmt.Errorf("simulated clsact unavailable"),
			wantStillMissing: []string{"eth1 (WAN, handle 0x2023 missing)"},
			wantFatal:        false,
		},
		{
			name:             "dae0 missing is fatal and not self-healed",
			known:            map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters:          map[string][]netlink.Filter{"eth0": mkFilters(0x2023)},
			bound:            []boundIface{{"dae0", "dae0", 0x2022}, {"eth0", "LAN", 0x2023}},
			wantStillMissing: []string{"dae0 (dae0, handle 0x2022 missing)"},
			wantFatal:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// filters is a mutable copy so a successful rebind can "add" the
			// missing filter, mirroring a real re-attach.
			filters := map[string][]netlink.Filter{}
			for k, v := range tt.filters {
				filters[k] = v
			}
			linkByName = func(name string) (netlink.Link, error) {
				if l, ok := tt.known[name]; ok {
					return l, nil
				}
				return nil, fmt.Errorf("link %s not found", name)
			}
			filterLister = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
				if fs, ok := filters[link.Attrs().Name]; ok {
					return fs, nil
				}
				return nil, nil
			}
			rebindLanFn = func(c *controlPlaneCore, name string) error {
				if tt.lanRebindErr != nil {
					return tt.lanRebindErr
				}
				if tt.lanRebindFixes {
					filters[name] = mkFilters(0x2023)
				}
				return nil
			}
			rebindWanFn = func(c *controlPlaneCore, name string) error {
				if tt.wanRebindErr != nil {
					return tt.wanRebindErr
				}
				if tt.wanRebindFixes {
					filters[name] = mkFilters(0x2023)
				}
				return nil
			}

			c := &controlPlaneCore{datapathIfaces: tt.bound}
			c.log = logrus.New()
			c.log.SetOutput(io.Discard)

			stillMissing, fatal := c.repairDatapathBindings()

			if fatal != tt.wantFatal {
				t.Errorf("fatal = %v, want %v", fatal, tt.wantFatal)
			}
			if len(tt.wantStillMissing) == 0 {
				if len(stillMissing) != 0 {
					t.Fatalf("expected no still-missing, got %v", stillMissing)
				}
				return
			}
			if len(stillMissing) == 0 {
				t.Fatalf("expected still-missing %v, got none", tt.wantStillMissing)
			}
			for _, want := range tt.wantStillMissing {
				found := false
				for _, m := range stillMissing {
					if m == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("still-missing %q not found in %v", want, stillMissing)
				}
			}
		})
	}
}

func TestHasDaeTcFilter(t *testing.T) {
	origFilterLister := filterLister
	t.Cleanup(func() { filterLister = origFilterLister })

	link := mkLink("eth0")

	tests := []struct {
		name    string
		filters []netlink.Filter
		major   uint16
		want    bool
	}{
		{"matching major", mkFilters(0x2023), 0x2023, true},
		{"non-matching major", mkFilters(0x2022), 0x2023, false},
		{"no filters", nil, 0x2023, false},
		{"dae0 major", mkFilters(0x2022), 0x2022, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filterLister = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
				return tt.filters, nil
			}
			if got := hasDaeTcFilter(link, tt.major); got != tt.want {
				t.Errorf("hasDaeTcFilter(%#x) = %v, want %v", tt.major, got, tt.want)
			}
		})
	}
}

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
