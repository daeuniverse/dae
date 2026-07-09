package control

import (
	"fmt"
	"testing"

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

	tests := []struct {
		name         string
		known        map[string]netlink.Link
		filters      map[string][]netlink.Filter
		lan          []string
		wan          []string
		wantEmpty    bool
		wantContains []string
	}{
		{
			name:      "all bindings present",
			known:     map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters:   map[string][]netlink.Filter{"dae0": mkFilters(0x2022), "eth0": mkFilters(0x2023)},
			lan:       []string{"eth0"},
			wan:       nil,
			wantEmpty: true,
		},
		{
			name:         "dae0 filter missing",
			known:        map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters:      map[string][]netlink.Filter{"eth0": mkFilters(0x2023)},
			lan:          []string{"eth0"},
			wan:          nil,
			wantEmpty:    false,
			wantContains: []string{"dae0 (dae0, handle 0x2022 missing)"},
		},
		{
			name:         "lan filter missing",
			known:        map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters:      map[string][]netlink.Filter{"dae0": mkFilters(0x2022)},
			lan:          []string{"eth0"},
			wan:          nil,
			wantEmpty:    false,
			wantContains: []string{"eth0 (LAN, handle 0x2023 missing)"},
		},
		{
			name:         "wan filter missing",
			known:        map[string]netlink.Link{"dae0": dae0, "eth1": eth1},
			filters:      map[string][]netlink.Filter{"dae0": mkFilters(0x2022)},
			lan:          nil,
			wan:          []string{"eth1"},
			wantEmpty:    false,
			wantContains: []string{"eth1 (WAN, handle 0x2023 missing)"},
		},
		{
			name:         "interface not found",
			known:        map[string]netlink.Link{"dae0": dae0},
			filters:      map[string][]netlink.Filter{"dae0": mkFilters(0x2022)},
			lan:          []string{"eth0"},
			wan:          nil,
			wantEmpty:    false,
			wantContains: []string{"eth0 (LAN, link not found)"},
		},
		{
			name:      "handles from egress parent only",
			known:     map[string]netlink.Link{"dae0": dae0, "eth0": eth0},
			filters:   map[string][]netlink.Filter{"dae0": mkFilters(0x2022), "eth0": mkFilters(0x2023)},
			lan:       []string{"eth0"},
			wan:       nil,
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

			c := &controlPlaneCore{}
			missing := c.validateDatapathBindings(tt.lan, tt.wan)

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
