package config

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestBootstrapResolvers_DefaultWhenUnset(t *testing.T) {
	got, err := BootstrapResolvers(&Global{})
	if err != nil {
		t.Fatalf("BootstrapResolvers() error = %v", err)
	}

	want := []netip.AddrPort{
		netip.MustParseAddrPort("119.29.29.29:53"),
		netip.MustParseAddrPort("223.5.5.5:53"),
	}
	if len(got) != len(want) {
		t.Fatalf("len(BootstrapResolvers()) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("BootstrapResolvers()[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestBootstrapResolvers_ExplicitOverrideDisablesDefaults(t *testing.T) {
	got, err := BootstrapResolvers(&Global{
		BootstrapResolver: "9.9.9.9:53",
	})
	if err != nil {
		t.Fatalf("BootstrapResolvers() error = %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("len(BootstrapResolvers()) = %d, want 1", len(got))
	}
	if got[0] != netip.MustParseAddrPort("9.9.9.9:53") {
		t.Fatalf("BootstrapResolvers()[0] = %v, want 9.9.9.9:53", got[0])
	}
}

func TestNewRejectsInvalidBootstrapResolverEarly(t *testing.T) {
	sections, err := config_parser.Parse(`
global {
    bootstrap_resolver: invalid
}
routing {
    fallback: direct
}
`)
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	_, err = New(sections)
	if err == nil {
		t.Fatal("expected invalid bootstrap_resolver to fail during config.New")
	}
}
