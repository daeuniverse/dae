package control

import (
	"fmt"
	"io"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// mkLink returns a minimal netlink.Link (a *netlink.Dummy) without touching the
// real kernel. Dummy implements the Link interface and its Attrs().Name is what
// our mocked filterLister keys on.
func mkLink(name string) netlink.Link {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

// mkFilters wraps the given full handles into a netlink.Filter list using
// GenericFilter (handle-only) so they exercise the handle-matching path.
// The program-aware path is covered by mkBpfFilters.
func mkFilters(handles ...uint32) []netlink.Filter {
	var fs []netlink.Filter
	for _, h := range handles {
		fs = append(fs, &netlink.GenericFilter{FilterAttrs: netlink.FilterAttrs{Handle: h}})
	}
	return fs
}

// mkBpfFilters wraps handles into *netlink.BpfFilter with the given attached
// program ids, so the program-aware path of hasDaeTcFilter can be exercised.
func mkBpfFilters(handles []uint32, ids []int) []netlink.Filter {
	var fs []netlink.Filter
	for i, h := range handles {
		id := 0
		if ids != nil && i < len(ids) {
			id = ids[i]
		}
		fs = append(fs, &netlink.BpfFilter{
			FilterAttrs:  netlink.FilterAttrs{Handle: h},
			DirectAction: true,
			Id:           id,
		})
	}
	return fs
}

// Full TC handles used by the datapath (flip=0 here to keep tests deterministic).
const (
	handleDae0  = uint32(0x20220002)
	handleLanIn = uint32(0x20230004)
	handleLanEg = uint32(0x20230002)
	handleWanIn = uint32(0x20230002)
	handleWanEg = uint32(0x20230004)
)

// mkTestProg loads a trivial eBPF program so the program-aware validation path
// can be exercised against a real, kernel-assigned program id. It skips the
// test when the kernel cannot load eBPF programs (e.g. CI without CAP_BPF).
func mkTestProg(t *testing.T) *ebpf.Program {
	t.Helper()
	spec := &ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	}
	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		t.Skipf("cannot create test eBPF program (kernel may lack support): %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	return prog
}

func TestValidateDatapathBindings(t *testing.T) {
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
	// successful bind: the *resolved* interface name, the expected label, and
	// the full TC filter handle(s). prog is nil here, so validation degrades to
	// a handle-only check (the program-aware path is covered separately).
	tests := []struct {
		name         string
		known        map[string]netlink.Link
		filters      map[string][]netlink.Filter
		bound        []boundIface
		wantEmpty    bool
		wantContains []string
	}{
		{
			name:  "all bindings present",
			known: map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters: map[string][]netlink.Filter{
				"dae0": mkFilters(handleDae0),
				"eth0": mkFilters(handleLanIn, handleLanEg),
			},
			bound: []boundIface{
				{name: "dae0", label: "dae0", filters: []boundFilter{{handle: handleDae0}}},
				{name: "eth0", label: "LAN", filters: []boundFilter{{handle: handleLanIn}, {handle: handleLanEg}}},
			},
			wantEmpty: true,
		},
		{
			name:   "dae0 filter missing",
			known:  map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters: map[string][]netlink.Filter{"eth0": mkFilters(handleLanIn, handleLanEg)},
			bound: []boundIface{
				{name: "dae0", label: "dae0", filters: []boundFilter{{handle: handleDae0}}},
				{name: "eth0", label: "LAN", filters: []boundFilter{{handle: handleLanIn}, {handle: handleLanEg}}},
			},
			wantEmpty:    false,
			wantContains: []string{fmt.Sprintf("dae0 (dae0, handle 0x%x missing or program mismatch)", handleDae0)},
		},
		{
			name:   "lan filter missing",
			known:  map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters: map[string][]netlink.Filter{"dae0": mkFilters(handleDae0)},
			bound: []boundIface{
				{name: "dae0", label: "dae0", filters: []boundFilter{{handle: handleDae0}}},
				{name: "eth0", label: "LAN", filters: []boundFilter{{handle: handleLanIn}, {handle: handleLanEg}}},
			},
			wantEmpty:    false,
			wantContains: []string{fmt.Sprintf("eth0 (LAN, handle 0x%x missing or program mismatch)", handleLanIn)},
		},
		{
			name:   "wan filter missing",
			known:  map[string]netlink.Link{"dae0": dae0, "eth1": eth1},
			filters: map[string][]netlink.Filter{"dae0": mkFilters(handleDae0)},
			bound: []boundIface{
				{name: "dae0", label: "dae0", filters: []boundFilter{{handle: handleDae0}}},
				{name: "eth1", label: "WAN", filters: []boundFilter{{handle: handleWanIn}, {handle: handleWanEg}}},
			},
			wantEmpty:    false,
			wantContains: []string{fmt.Sprintf("eth1 (WAN, handle 0x%x missing or program mismatch)", handleWanIn)},
		},
		{
			name:   "interface not found",
			known:  map[string]netlink.Link{"dae0": dae0},
			filters: map[string][]netlink.Filter{"dae0": mkFilters(handleDae0)},
			bound: []boundIface{
				{name: "dae0", label: "dae0", filters: []boundFilter{{handle: handleDae0}}},
				{name: "eth0", label: "LAN", filters: []boundFilter{{handle: handleLanIn}, {handle: handleLanEg}}},
			},
			wantEmpty:    false,
			wantContains: []string{"eth0 (LAN, link not found)"},
		},
		{
			name:      "no bindings recorded",
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
		name             string
		known            map[string]netlink.Link
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
			name:  "LAN missing then self-healed",
			known: map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters: map[string][]netlink.Filter{"dae0": mkFilters(handleDae0)},
			bound: []boundIface{
				{name: "dae0", label: "dae0", filters: []boundFilter{{handle: handleDae0}}},
				{name: "eth0", label: "LAN", filters: []boundFilter{{handle: handleLanIn}, {handle: handleLanEg}}},
			},
			lanRebindFixes: true,
			wantFatal:      false,
		},
		{
			name:  "WAN missing but rebind fails (warn only)",
			known: map[string]netlink.Link{"dae0": dae0, "eth1": eth1},
			filters: map[string][]netlink.Filter{"dae0": mkFilters(handleDae0)},
			bound: []boundIface{
				{name: "dae0", label: "dae0", filters: []boundFilter{{handle: handleDae0}}},
				{name: "eth1", label: "WAN", filters: []boundFilter{{handle: handleWanIn}, {handle: handleWanEg}}},
			},
			wanRebindErr:     fmt.Errorf("simulated clsact unavailable"),
			wantStillMissing: []string{fmt.Sprintf("eth1 (WAN, handle 0x%x missing or program mismatch)", handleWanIn)},
			wantFatal:        false,
		},
		{
			name:  "dae0 missing is fatal and not self-healed",
			known: map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters: map[string][]netlink.Filter{"eth0": mkFilters(handleLanIn, handleLanEg)},
			bound: []boundIface{
				{name: "dae0", label: "dae0", filters: []boundFilter{{handle: handleDae0}}},
				{name: "eth0", label: "LAN", filters: []boundFilter{{handle: handleLanIn}, {handle: handleLanEg}}},
			},
			wantStillMissing: []string{fmt.Sprintf("dae0 (dae0, handle 0x%x missing or program mismatch)", handleDae0)},
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
					filters[name] = mkFilters(handleLanIn, handleLanEg)
				}
				return nil
			}
			rebindWanFn = func(c *controlPlaneCore, name string) error {
				if tt.wanRebindErr != nil {
					return tt.wanRebindErr
				}
				if tt.wanRebindFixes {
					filters[name] = mkFilters(handleWanIn, handleWanEg)
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
	parents := []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS}

	t.Run("handle present, prog nil degrades to match", func(t *testing.T) {
		filterLister = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return mkBpfFilters([]uint32{handleLanIn}, []int{123}), nil
		}
		if !hasDaeTcFilter(link, handleLanIn, parents, nil) {
			t.Errorf("expected match (handle present, prog nil -> degrade to handle)")
		}
	})

	t.Run("handle mismatch", func(t *testing.T) {
		filterLister = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return mkBpfFilters([]uint32{handleLanIn}, []int{123}), nil
		}
		if hasDaeTcFilter(link, handleLanEg, parents, nil) {
			t.Errorf("expected no match for wrong handle")
		}
	})

	t.Run("no filters", func(t *testing.T) {
		filterLister = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return nil, nil
		}
		if hasDaeTcFilter(link, handleLanIn, parents, nil) {
			t.Errorf("expected no match when no filters attached")
		}
	})

	t.Run("program mismatch is a zombie", func(t *testing.T) {
		prog := mkTestProg(t)
		wantID, ok := expectedProgID(prog)
		if !ok {
			t.Skip("cannot resolve program id")
		}
		filterLister = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			// attached id differs from the expected program id -> zombie.
			return mkBpfFilters([]uint32{handleLanIn}, []int{int(wantID) + 1}), nil
		}
		if hasDaeTcFilter(link, handleLanIn, parents, prog) {
			t.Errorf("expected zombie (program id mismatch) to be rejected")
		}
	})

	t.Run("program match is healthy", func(t *testing.T) {
		prog := mkTestProg(t)
		wantID, ok := expectedProgID(prog)
		if !ok {
			t.Skip("cannot resolve program id")
		}
		filterLister = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return mkBpfFilters([]uint32{handleLanIn}, []int{int(wantID)}), nil
		}
		if !hasDaeTcFilter(link, handleLanIn, parents, prog) {
			t.Errorf("expected healthy filter (program id matches) to pass")
		}
	})

	t.Run("kernel reports no id degrades to handle match", func(t *testing.T) {
		prog := mkTestProg(t)
		filterLister = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return mkBpfFilters([]uint32{handleLanIn}, []int{0}), nil
		}
		if !hasDaeTcFilter(link, handleLanIn, parents, prog) {
			t.Errorf("expected degrade to handle match when kernel id missing")
		}
	})

	t.Run("non-bpf filter with matching handle degrades to match", func(t *testing.T) {
		prog := mkTestProg(t)
		filterLister = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return mkFilters(handleLanIn), nil
		}
		if !hasDaeTcFilter(link, handleLanIn, parents, prog) {
			t.Errorf("expected non-bpf filter to degrade to handle match")
		}
	})
}
