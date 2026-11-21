//go:build dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The event rate-limit constants are owned by Go (event_rate_contract.go) and
// injected into the .rodata variable EVENT_RATE at load time; the bpf_stats_map
// key domain is owned by C and read back by Go. These tests pin both halves of
// the contract at the source level, so a C-side rename, field reorder,
// fallback-constant drift or key renumbering turns the Go Unit Test gate red
// instead of silently falling back to clang initializers (or reading the wrong
// counter) at runtime.

var (
	// matches "const volatile struct dae_event_rate EVENT_RATE = { ... };"
	// and captures the struct tag name and the variable name.
	rodataVariablePattern = regexp.MustCompile(`(?m)const\s+volatile\s+struct\s+(\w+)\s+(\w+)\s*=`)

	// captures the declared field names of struct dae_event_rate in order.
	eventRateStructPattern = regexp.MustCompile(
		`struct\s+dae_event_rate\s*\{([^}]*)\}`)

	// captures " #define EVENT_RATE_KEY_MAX_FALLBACK <n>".
	rateKeyFallbackPattern = regexp.MustCompile(`(?m)#define\s+EVENT_RATE_KEY_MAX_FALLBACK\s+(\d+)`)

	// captures the body of "enum bpf_stats_key { ... }".
	bpfStatsEnumPattern = regexp.MustCompile(`enum\s+bpf_stats_key\s*\{([^}]*)\}`)

	// captures the body of "enum dae_event_type { ... }".
	daeEventTypeEnumPattern = regexp.MustCompile(`enum\s+dae_event_type\s*\{([^}]*)\}`)

	// captures "NAME = <n>" entries inside an enum body. Anchored at the start
	// of a line so the comment lines ("// key=0: ...") of the C enum do not
	// count as entries.
	enumEntryPattern = regexp.MustCompile(`(?m)^\s*(\w+)\s*=\s*(\d+)`)

	// captures " #define MAX_REDIRECT_TRACK_NUM <n>".
	redirectTrackNumPattern = regexp.MustCompile(`(?m)#define\s+MAX_REDIRECT_TRACK_NUM\s+(\d+)`)

	// captures " #define REDIRECT_REBIND_STALE_NS_FALLBACK <n>".
	redirectRebindStalePattern = regexp.MustCompile(`(?m)#define\s+REDIRECT_REBIND_STALE_NS_FALLBACK\s+(\d+)U?LL?`)
)

func TestBpfVariablesParityWithKernelSource(t *testing.T) {
	found := map[string]string{} // variable name -> struct tag name
	for _, m := range rodataVariablePattern.FindAllStringSubmatch(tproxySource, -1) {
		found[m[2]] = m[1]
	}

	for _, name := range expectedInjectedVariables {
		tag, ok := found[name]
		if !ok {
			t.Errorf("kernel source declares no `const volatile struct ... %s`; "+
				"bpf_utils.go injects it but the C-side declaration is gone "+
				"(renamed or removed?)", name)
			continue
		}
		if tag != "dae_param" && tag != "dae_event_rate" {
			t.Errorf("variable %s has unexpected struct type %q", name, tag)
		}
	}

	// The reverse direction: every const-volatile struct variable in the
	// kernel source must be covered by the Go injection list, otherwise it
	// would silently keep its clang fallback value in production.
	for name := range found {
		listed := slices.Contains(expectedInjectedVariables, name)
		if !listed {
			t.Errorf("kernel source declares const-volatile variable %q but "+
				"expectedInjectedVariables does not list it; it would keep its "+
				"clang fallback initializer instead of being injected by Go", name)
		}
	}
}

// stripCKernelComments removes block and line comments so source assertions
// match code only (the comments next to the raw-byte accessors quote the very
// expressions this test forbids).
func stripCKernelComments(src string) string {
	src = blockCommentPattern.ReplaceAllString(src, "")
	return lineCommentPattern.ReplaceAllString(src, "")
}

var (
	blockCommentPattern = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineCommentPattern  = regexp.MustCompile(`//[^\n]*`)

	// UAPI bitfields of struct iphdr/struct tcphdr. Their allocation order
	// follows the target's endianness, not the wire format, so reading them
	// directly made the datapath classify packets wrongly on big-endian
	// builds. The datapath must only touch the raw header bytes.
	bitfieldReadPattern = regexp.MustCompile(`->(ihl|version|doff|syn|ack|fin|rst|psh|ece|cwr|urg|res1)\b`)
)

func TestKernelSourceHasNoBitfieldHeaderReads(t *testing.T) {
	code := stripCKernelComments(tproxySource)
	// ctx->ihl is the parser scratch field (a plain __u8), not the UAPI
	// bitfield of struct iphdr.
	code = strings.ReplaceAll(code, "ctx->ihl", "ctx->scratch_ihl")

	for _, m := range bitfieldReadPattern.FindAllString(code, -1) {
		t.Errorf("kern/tproxy.c reads the UAPI bitfield %q; use the raw-byte "+
			"accessors (iphdr_ihl/iphdr_version/tcph_doff/tcph_flags) instead: "+
			"the bitfield layout is target-endian and misparses on big-endian builds", m)
	}
}

func TestEventRateStructLayoutContract(t *testing.T) {
	m := eventRateStructPattern.FindStringSubmatch(tproxySource)
	if m == nil {
		t.Fatal("struct dae_event_rate not found in kern/tproxy.c")
	}
	fieldPattern := regexp.MustCompile(`(__u\d+|\w+_t)\s+(\w+)\s*;`)
	var fields []string
	for _, fm := range fieldPattern.FindAllStringSubmatch(m[1], -1) {
		fields = append(fields, fm[2])
	}

	// Two u64 fields first (so the struct has no implicit padding between
	// them), then the reserved rate keys, then an explicit pad that keeps the
	// C sizeof free of alignment holes. eventRateValue mirrors this order
	// with an explicit trailing byte array to match the C sizeof; the parity
	// of the two sizes is enforced at load time by ebpf.VariableSpec.Set.
	want := []string{
		"window_ns",
		"redirect_rebind_stale_ns",
		"blocked_key",
		"redirect_rebind_key",
		"overflow_key",
		"syn_rebind_key",
		"stateless_tcp_key",
		"frag_tail_key",
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("struct dae_event_rate field order %v, want %v (no implicit padding allowed: the Go mirror is binary-injected)", fields, want)
	}
	if !regexp.MustCompile(`__u32\s+padding\s*\[2\]\s*;`).MatchString(m[1]) {
		t.Fatalf("struct dae_event_rate must end with an explicit `__u32 padding[2]` so its sizeof (48) matches the packed Go mirror; body: %s", m[1])
	}
}

func TestEventRateValueMatchesContract(t *testing.T) {
	// Anchors the injected value (and the contract symbols) in the
	// dae_stub_ebpf build, where bpf_utils.go — the production consumer —
	// is excluded: without this reference the mirror would be flagged
	// unused by the stub-tagged lint pass.
	v := eventRateValue()
	if v.WindowNs != blockedEventRateWindowNs {
		t.Fatalf("EVENT_RATE window %d != contract %d", v.WindowNs, blockedEventRateWindowNs)
	}
	if v.RedirectRebindStaleNs != redirectRebindStaleNs {
		t.Fatalf("EVENT_RATE rebind window %d != contract %d", v.RedirectRebindStaleNs, redirectRebindStaleNs)
	}
	if v.BlockedKey != blockedEventRateKey {
		t.Fatalf("EVENT_RATE blocked key %d != contract %d", v.BlockedKey, blockedEventRateKey)
	}
	if v.RedirectRebindKey != redirectRebindEventRateKey {
		t.Fatalf("EVENT_RATE redirect rebind key %d != contract %d", v.RedirectRebindKey, redirectRebindEventRateKey)
	}
	if v.OverflowKey != overflowEventRateKey {
		t.Fatalf("EVENT_RATE overflow key %d != contract %d", v.OverflowKey, overflowEventRateKey)
	}
	if v.SynRebindKey != synRebindEventRateKey {
		t.Fatalf("EVENT_RATE syn rebind key %d != contract %d", v.SynRebindKey, synRebindEventRateKey)
	}
	if v.StatelessTCPKey != statelessTCPEventRateKey {
		t.Fatalf("EVENT_RATE stateless TCP key %d != contract %d", v.StatelessTCPKey, statelessTCPEventRateKey)
	}
	if v.FragTailKey != fragTailEventRateKey {
		t.Fatalf("EVENT_RATE fragment tail key %d != contract %d", v.FragTailKey, fragTailEventRateKey)
	}
}

func TestEventRateFallbackConstantsMatchGoOwner(t *testing.T) {
	m := rateKeyFallbackPattern.FindStringSubmatch(tproxySource)
	if m == nil {
		t.Fatal("#define EVENT_RATE_KEY_MAX_FALLBACK not found in kern/tproxy.c")
	}
	fallback, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		t.Fatalf("parse fallback key %q: %v", m[1], err)
	}
	if uint32(fallback) != eventRateMapKeyMax {
		t.Fatalf("C fallback EVENT_RATE_KEY_MAX_FALLBACK=%d diverges from the Go-owned eventRateMapKeyMax=%d; the map capacity derives from the Go value while the C code uses the fallback",
			fallback, eventRateMapKeyMax)
	}
	rebind := redirectRebindStalePattern.FindStringSubmatch(tproxySource)
	if rebind == nil {
		t.Fatal("#define REDIRECT_REBIND_STALE_NS_FALLBACK not found in kern/tproxy.c")
	}
	stale, err := strconv.ParseUint(rebind[1], 10, 64)
	if err != nil {
		t.Fatalf("parse rebind window %q: %v", rebind[1], err)
	}
	if stale != redirectRebindStaleNs {
		t.Fatalf("C fallback REDIRECT_REBIND_STALE_NS_FALLBACK=%d diverges from the Go-owned redirectRebindStaleNs=%d", stale, redirectRebindStaleNs)
	}
}

// TestDaeEventTypeNumbersMatchKernelSource pins the ringbuf event numbering
// against the Go iota table in event_ringbuf.go. The numbers are a wire
// contract: the kernel writes the type into the record and userspace decodes it
// without any other discriminator, so an inserted or removed entry on either
// side silently turns one event into another. Two of the entries are reserved
// (established TCP without cached routing, forwarded fragment tails) because
// they are counted and summarised instead of emitted; this test is what keeps
// them reserved and keeps the emitted types on their historical numbers.
func TestDaeEventTypeNumbersMatchKernelSource(t *testing.T) {
	m := daeEventTypeEnumPattern.FindStringSubmatch(tproxySource)
	if m == nil {
		t.Fatal("enum dae_event_type not found in kern/tproxy.c")
	}
	cTypes := map[string]uint32{}
	for _, em := range enumEntryPattern.FindAllStringSubmatch(m[1], -1) {
		value, err := strconv.ParseUint(em[2], 10, 32)
		if err != nil {
			t.Fatalf("parse enum entry %s: %v", em[0], err)
		}
		cTypes[em[1]] = uint32(value)
	}

	contract := []struct {
		cName  string
		goType uint32
	}{
		{"DAE_EVENT_BLOCKED", daeEventBlocked},
		{"DAE_EVENT_UDP_CONN_OVERFLOW", daeEventUdpConnOverflow},
		{"DAE_EVENT_TCP_CONN_OVERFLOW", daeEventTcpConnOverflow},
		{"DAE_EVENT_BLOCKED_ALIVE", daeEventBlockedAlive},
		{"DAE_EVENT_REDIRECT_REBIND_REJECTED", daeEventRedirectRebindRejected},
		{"DAE_EVENT_SYN_REBIND_REJECTED", daeEventSynRebindRejected},
		{"DAE_EVENT_RESERVED_STATELESS_TCP_PASSTHROUGH", daeEventReservedStatelessTcpPassthrough},
		{"DAE_EVENT_RESERVED_FRAG_TAIL_PASSED", daeEventReservedFragTailPassed},
		{"DAE_EVENT_REDIRECT_UPDATE_FAILED", daeEventRedirectUpdateFailed},
		{"DAE_EVENT_SYN_REBIND_REROUTED", daeEventSynRebindRerouted},
		{"DAE_EVENT_REJECTED", daeEventRejected},
	}
	for _, entry := range contract {
		value, ok := cTypes[entry.cName]
		if !ok {
			t.Errorf("enum dae_event_type has no %s entry", entry.cName)
			continue
		}
		if value != entry.goType {
			t.Errorf("event type %s = %d in C but %d in Go; the ringbuf consumer would decode it as another event",
				entry.cName, value, entry.goType)
		}
	}
	if len(cTypes) != len(contract) {
		t.Errorf("enum dae_event_type declares %d entries but Go mirrors %d; every emitted type needs a Go-side decoder (or the enum has a stale entry)",
			len(cTypes), len(contract))
	}
}

// TestBpfStatsKeysParityWithKernelSource pins the bpf_stats_map key domain:
// every counter Go reads back must exist in enum bpf_stats_key with the same
// number, the enum must not carry keys Go does not know about, and the ARRAY
// capacity must be the terminal enum entry.
func TestBpfStatsKeysParityWithKernelSource(t *testing.T) {
	m := bpfStatsEnumPattern.FindStringSubmatch(tproxySource)
	if m == nil {
		t.Fatal("enum bpf_stats_key not found in kern/tproxy.c")
	}
	cKeys := map[string]uint32{}
	for _, em := range enumEntryPattern.FindAllStringSubmatch(m[1], -1) {
		value, err := strconv.ParseUint(em[2], 10, 32)
		if err != nil {
			t.Fatalf("parse enum entry %s: %v", em[0], err)
		}
		cKeys[em[1]] = uint32(value)
	}

	contract := []struct {
		cName string
		goKey uint32
	}{
		{"BPF_STATS_UDP_CONN_OVERFLOW", bpfStatsUDPConnOverflow},
		{"BPF_STATS_TCP_CONN_OVERFLOW", bpfStatsTCPConnOverflow},
		{"BPF_STATS_REDIRECT_OVERFLOW", bpfStatsRedirectOverflow},
		{"BPF_STATS_REDIRECT_UPDATE_FAILED", bpfStatsRedirectUpdateFailed},
		{"BPF_STATS_REDIRECT_REBIND_REJECTED", bpfStatsRedirectRebindRejected},
		{"BPF_STATS_SYN_REBIND_REJECTED", bpfStatsSynRebindRejected},
		{"BPF_STATS_STATELESS_TCP_PASSTHROUGH", bpfStatsStatelessTCPPassthrough},
		{"BPF_STATS_FRAG_TAIL_PASSED", bpfStatsFragTailPassed},
		{"BPF_STATS_PARSE_UNSUPPORTED_L4", bpfStatsParseUnsupportedL4},
		{"BPF_STATS_UNSOLICITED_UDP_SEEN", bpfStatsUnsolicitedUDPSeen},
		{"BPF_STATS_SOCKMARK_FALLBACK", bpfStatsSockmarkFallback},
		{"BPF_STATS_EVENT_DROP", bpfStatsEventDrop},
		{"BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE", bpfStatsRebindReroutedAfterEpochChange},
	}
	for _, entry := range contract {
		value, ok := cKeys[entry.cName]
		if !ok {
			t.Errorf("enum bpf_stats_key has no %s entry", entry.cName)
			continue
		}
		if value != entry.goKey {
			t.Errorf("bpf_stats_map key %s = %d in C but %d in Go; the Go reader would read the wrong counter",
				entry.cName, value, entry.goKey)
		}
	}

	// BPF_STATS_MAX is the ARRAY capacity, i.e. one past the last valid key. It
	// is derived from the table above instead of being mirrored as a Go
	// constant: adding a key in C without covering it here then fails, and the
	// Go side never owns a second copy of the C macro.
	if got := cKeys["BPF_STATS_MAX"]; got != uint32(len(contract)) {
		t.Errorf("BPF_STATS_MAX = %d in C but %d keys are covered here", got, len(contract))
	}
	// The C enum carries one entry that is not a key: BPF_STATS_MAX, the array
	// capacity. Counting it separately keeps both invariants without a Go-side
	// copy of the C macro (a Go mirror would be a second owner of that value).
	if len(cKeys) != len(contract)+1 {
		t.Errorf("enum bpf_stats_key declares %d entries (%d keys plus BPF_STATS_MAX) but Go mirrors %d keys; every key needs a Go-side reader (or the enum has a stale entry)",
			len(cKeys), len(contract), len(contract))
	}
	if !regexp.MustCompile(`__uint\(max_entries,\s*BPF_STATS_MAX\)`).MatchString(tproxySource) {
		t.Error("bpf_stats_map must size itself from BPF_STATS_MAX so the ARRAY capacity cannot drift from the enum")
	}
}

// TestRedirectTrackCapacityParityWithKernelSource pins the single-owner
// contract of tuneRedirectTrackMap: the Go default must mirror the C map
// declaration, which is what makes the load-time cross-check meaningful.
func TestRedirectTrackCapacityParityWithKernelSource(t *testing.T) {
	m := redirectTrackNumPattern.FindStringSubmatch(tproxySource)
	if m == nil {
		t.Fatal("#define MAX_REDIRECT_TRACK_NUM not found in kern/tproxy.c")
	}
	want, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		t.Fatalf("parse MAX_REDIRECT_TRACK_NUM %q: %v", m[1], err)
	}
	if uint32(want) != defaultRedirectTrackMapMaxEntries {
		t.Fatalf("C MAX_REDIRECT_TRACK_NUM=%d diverges from Go defaultRedirectTrackMapMaxEntries=%d; tuneRedirectTrackMap cross-checks the compiled capacity against the Go value and would fail the load",
			want, defaultRedirectTrackMapMaxEntries)
	}
}
