package config

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestNewTracksExplicitSoMarkFromDaeZero(t *testing.T) {
	sections, err := config_parser.Parse(`
global {
    so_mark_from_dae: 0
}
routing {
    fallback: direct
}
`)
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	conf, err := New(sections)
	if err != nil {
		t.Fatalf("New error = %v", err)
	}

	if !conf.Global.SoMarkFromDaeSet {
		t.Fatal("SoMarkFromDaeSet = false, want true")
	}
	if conf.Global.SoMarkFromDae != 0 {
		t.Fatalf("SoMarkFromDae = %#x, want 0", conf.Global.SoMarkFromDae)
	}
}

func TestNewLeavesSoMarkFromDaeUnsetWhenMissing(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing {
    fallback: direct
}
`)
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	conf, err := New(sections)
	if err != nil {
		t.Fatalf("New error = %v", err)
	}

	if conf.Global.SoMarkFromDaeSet {
		t.Fatal("SoMarkFromDaeSet = true, want false")
	}
	if conf.Global.SoMarkFromDae != 0 {
		t.Fatalf("SoMarkFromDae = %#x, want 0", conf.Global.SoMarkFromDae)
	}
}
