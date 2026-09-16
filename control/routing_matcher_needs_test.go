package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

// TestComputeRoutingMatcherNeeds locks the fact-gating inventory: only the
// rule types present in the compiled set enable their binary-key builds, and
// newFacts leaves gated keys empty while filling requested ones.
func TestRoutingMatcherNeedsGatesFactBuilds(t *testing.T) {
	mk := func(mt consts.MatchType) compiledRoutingMatch {
		return compiledRoutingMatch{matchType: mt}
	}
	portOnly := []compiledRoutingMatch{mk(consts.MatchType_Port), mk(consts.MatchType_Fallback)}
	needs := computeRoutingMatcherNeeds(portOnly)
	if needs.ipSetBin || needs.sourceIPSetB || needs.macBin || needs.domainBitmap {
		t.Fatalf("port-only rules must need no bin facts: %+v", needs)
	}

	all := []compiledRoutingMatch{
		mk(consts.MatchType_IpSet),
		mk(consts.MatchType_SourceIpSet),
		mk(consts.MatchType_Mac),
		mk(consts.MatchType_DomainSet),
	}
	if needs = computeRoutingMatcherNeeds(all); !needs.ipSetBin || !needs.sourceIPSetB || !needs.macBin || !needs.domainBitmap {
		t.Fatalf("all-type rules must require every bin fact: %+v", needs)
	}

	m := &RoutingMatcher{needs: needs}
	facts, err := m.newFacts(
		srcAddr16(t, "10.0.0.1"),
		dstAddr16(t, "8.8.8.8"),
		1234, 443,
		consts.IpVersion_4, consts.L4ProtoStr_TCP.ToL4ProtoType(),
		"", [16]uint8{}, 0, [16]uint8{},
	)
	if err != nil {
		t.Fatalf("newFacts: %v", err)
	}
	if facts.ipSetBin == "" || facts.sourceIPSetBin == "" {
		t.Fatal("required ip bins were not built")
	}
	// Without a domain there is nothing to match even when DomainSet exists.
	if facts.domainBitmap != nil {
		t.Fatal("domainBitmap built without a domain")
	}
}

// A port-only matcher never touches the LPM bins: verify by checking the
// gated matcher reports no error evaluating such a rule with empty bins.
func TestMatchCompiledMatchWithGatedEmptyBins(t *testing.T) {
	m := &RoutingMatcher{}
	facts, err := m.newFacts(srcAddr16(t, "10.0.0.1"), dstAddr16(t, "8.8.8.8"), 1234, 80,
		consts.IpVersion_4, consts.L4ProtoStr_TCP.ToL4ProtoType(), "", [16]uint8{}, 0, [16]uint8{})
	if err != nil {
		t.Fatalf("newFacts: %v", err)
	}
	ok, err := m.matchCompiledMatch(0, compiledRoutingMatch{
		matchType: consts.MatchType_Port, portStart: 80, portEnd: 80,
	}, &facts)
	if err != nil || !ok {
		t.Fatalf("port match = (%v, %v), want (true, nil)", ok, err)
	}
}

func srcAddr16(t *testing.T, s string) [16]uint8 {
	t.Helper()
	ip := netip.MustParseAddr(s).As16()
	var a [16]uint8
	copy(a[:], ip[:])
	return a
}

func dstAddr16(t *testing.T, s string) [16]uint8 { return srcAddr16(t, s) }
