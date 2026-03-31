package common

import "testing"

func TestEffectiveSoMarkFromDaeDefaultsToInternalMark(t *testing.T) {
	if got := EffectiveSoMarkFromDae(0); got != InternalSoMarkFromDae {
		t.Fatalf("EffectiveSoMarkFromDae(0) = %#x, want %#x", got, InternalSoMarkFromDae)
	}
}

func TestEffectiveSoMarkFromDaePreservesConfiguredMark(t *testing.T) {
	const configured uint32 = 0x2023
	if got := EffectiveSoMarkFromDae(configured); got != configured {
		t.Fatalf("EffectiveSoMarkFromDae(%#x) = %#x, want %#x", configured, got, configured)
	}
}
