/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

// Datapath contract constants owned by userspace. Two key domains live here:
//
//   - alive_block_rate_map keys (event rate limiting) and the rebind policy
//     window, injected into the eBPF .rodata variable EVENT_RATE (struct
//     dae_event_rate in kern/tproxy.c) before LoadAndAssign, and
//   - bpf_stats_map keys (per-packet counters) read back on the janitor tick.
//
// This file deliberately carries no build tag: both the real-eBPF build
// (bpf_utils.go) and the dae_stub_ebpf test build (parity tests) must see the
// same contract values.
const (
	// Reserved alive_block_rate_map keys. Outbound ids live in the 0..255
	// u8 domain, so 256 and above can never collide with a real outbound
	// id. Each key is an independent 1s budget; the map capacity derives
	// from eventRateMapKeyMax, so adding a key here and to the C fallback
	// macro is all that is needed (guarded by the source parity tests).
	blockedEventRateKey        = uint32(256)
	redirectRebindEventRateKey = uint32(257)
	overflowEventRateKey       = uint32(258)
	synRebindEventRateKey      = uint32(259)
	statelessTCPEventRateKey   = uint32(260)
	fragTailEventRateKey       = uint32(261)

	// eventRateMapKeyMax is the highest reserved key; the ARRAY capacity is
	// keyMax+1. It mirrors EVENT_RATE_KEY_MAX_FALLBACK in kern/tproxy.c.
	eventRateMapKeyMax = fragTailEventRateKey

	// blockedEventRateWindowNs is the per-key minimum spacing between
	// emissions (1s).
	blockedEventRateWindowNs = uint64(1_000_000_000)

	// redirectRebindStaleNs is how long a redirect_track reply binding stays
	// frozen against a different publisher. A roaming LAN client is
	// silent for less than this before it reappears on a new interface.
	redirectRebindStaleNs = uint64(2_000_000_000)
)

// bpf_stats_map keys, mirroring enum bpf_stats_key in kern/tproxy.c. Keep the
// order and the terminal entry count in sync (guarded by
// TestBpfStatsKeysParityWithKernelSource).
const (
	// bpfStatsUDPConnOverflow and bpfStatsTCPConnOverflow drive the janitor's
	// pressure mode: a growing value means the corresponding conn-state map
	// is full.
	bpfStatsUDPConnOverflow = uint32(0)
	bpfStatsTCPConnOverflow = uint32(1)
	// bpfStatsRedirectOverflow counts redirect_track updates rejected by a
	// full map; bpfStatsRedirectUpdateFailed counts every other update error.
	bpfStatsRedirectOverflow     = uint32(2)
	bpfStatsRedirectUpdateFailed = uint32(3)
	// bpfStatsRedirectRebindRejected counts reply bindings kept against a
	// competing publisher on a fresh entry.
	bpfStatsRedirectRebindRejected = uint32(4)
	// bpfStatsSynRebindRejected counts pure SYNs refused rewrite of a live
	// flow's routing metadata.
	bpfStatsSynRebindRejected = uint32(5)
	// bpfStatsStatelessTCPPassthrough counts established TCP forwarded with no
	// cached routing decision.
	bpfStatsStatelessTCPPassthrough = uint32(6)
	// bpfStatsFragTailPassed counts non-initial fragments forwarded without
	// routing.
	bpfStatsFragTailPassed = uint32(7)
	// bpfStatsParseUnsupportedL4 counts packets whose IP header parsed but
	// whose L4 protocol is not TCP/UDP.
	bpfStatsParseUnsupportedL4 = uint32(8)
	// bpfStatsUnsolicitedUDPSeen counts WAN-ingress UDP packets whose flow had
	// no forward state yet. Observability only: the conn state is
	// still created, because the is_wan_ingress_direction marker it carries is
	// what keeps host-terminated UDP replies on the pass-through path.
	bpfStatsUnsolicitedUDPSeen = uint32(9)
	// bpfStatsSockmarkFallback counts pid_is_control_plane falling back to the
	// reserved-mark bit test.
	bpfStatsSockmarkFallback = uint32(10)
	// bpfStatsEventDrop counts datapath events dropped because the ringbuf had
	// no room. The consumers are advisory, but a dropped event must never be
	// invisible.
	bpfStatsEventDrop = uint32(11)
	// bpfStatsRebindReroutedAfterEpochChange counts pure SYNs that replaced a
	// live ACTIVE flow's cached routing because the flow's routing epoch or
	// datapath generation no longer matched the current one. It is the visible
	// half of "after the rules changed, a new connection uses the new rules";
	// the lock that protects a flow inside its own generation is counted as
	// bpfStatsSynRebindRejected.
	bpfStatsRebindReroutedAfterEpochChange = uint32(12)
)

// expectedInjectedVariables lists every .rodata variable this package promises
// to inject at load time. The completeness guard in
// loadBpfObjectsWithConstantsAndCustomizer fails the load when the constants
// map drifts from this list.
var expectedInjectedVariables = []string{
	"PARAM",
	"EVENT_RATE",
}

// bpfStatsSnapshot holds the bpf_stats_map counters that are read together on
// a health-check tick. The two conn-state overflow counters stay out of it:
// they are read on the (hotter) janitor cadence by readMapOverflowCounters and
// drive the janitor's pressure mode.
type bpfStatsSnapshot struct {
	// RedirectOverflow counts redirect_track updates rejected by a full map;
	// RedirectUpdateFailed counts every other update error.
	RedirectOverflow     uint64
	RedirectUpdateFailed uint64
	// RedirectRebindRejected counts reply bindings kept against a competing
	// publisher on a fresh entry.
	RedirectRebindRejected uint64
	// SynRebindRejected counts pure SYNs refused rewrite of a live flow's
	// routing metadata.
	SynRebindRejected uint64
	// StatelessTCPPassthrough counts established TCP forwarded with no cached
	// routing decision.
	StatelessTCPPassthrough uint64
	// FragTailPassed counts non-initial fragments forwarded without routing
	//.
	FragTailPassed uint64
	// ParseUnsupportedL4 counts packets whose IP header parsed but whose L4
	// protocol is not TCP/UDP.
	ParseUnsupportedL4 uint64
	// UnsolicitedUDPSeen counts WAN-ingress UDP packets of a flow that had no
	// forward state yet (; observability only, see the key comment).
	UnsolicitedUDPSeen uint64
	// SockmarkFallback counts pid_is_control_plane falling back to the
	// reserved-mark bit test.
	SockmarkFallback uint64
	// EventDrop counts events lost because the ringbuf was full.
	EventDrop uint64
	// RebindReroutedAfterEpochChange counts live flows whose cached routing was
	// replaced by the current generation on a pure SYN, because the flow
	// outlived a routing-epoch or datapath-generation change.
	RebindReroutedAfterEpochChange uint64
}

// eventRateSpec mirrors C struct dae_event_rate. The field order mirrors the
// C struct: the two u64 fields first, then the reserved rate keys, then an
// explicit 8-byte pad so the Go mirror's packed encoding matches the C
// sizeof exactly (48) with no implicit alignment holes on either side. Keep
// in sync with kern/tproxy.c (guarded by
// TestEventRateStructLayoutContract).
type eventRateSpec = struct {
	WindowNs              uint64
	RedirectRebindStaleNs uint64
	BlockedKey            uint32
	RedirectRebindKey     uint32
	OverflowKey           uint32
	SynRebindKey          uint32
	StatelessTCPKey       uint32
	FragTailKey           uint32
	_                     [8]byte
}

// eventRateValue returns the value injected into the eBPF .rodata variable
// EVENT_RATE (struct dae_event_rate in kern/tproxy.c) at load time.
func eventRateValue() eventRateSpec {
	return eventRateSpec{
		WindowNs:              blockedEventRateWindowNs,
		RedirectRebindStaleNs: redirectRebindStaleNs,
		BlockedKey:            blockedEventRateKey,
		RedirectRebindKey:     redirectRebindEventRateKey,
		OverflowKey:           overflowEventRateKey,
		SynRebindKey:          synRebindEventRateKey,
		StatelessTCPKey:       statelessTCPEventRateKey,
		FragTailKey:           fragTailEventRateKey,
	}
}
