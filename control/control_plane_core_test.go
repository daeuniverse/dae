package control

import (
	"fmt"
	"io"
	"testing"

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
