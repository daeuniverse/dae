// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>

// +build ignore

// Disable implicit CO-RE from vmlinux.h to bypass bad relocation.
// Note: Previously misattributed to GCC 15 DTE. The actual root cause is that
// pahole fails to parse DWARF5 debug info correctly, which strips UAPI structs
// from the generated BTF.
// Workaround for implicit CO-RE: compile kernel with CONFIG_DEBUG_INFO_DWARF4=y.
// However, it is highly recommended to keep this macro defined, as it still
// significantly improves overall compatibility across different environments.
#define BPF_NO_PRESERVE_ACCESS_INDEX 1

#include "headers/errno-base.h"
#include "headers/if_ether_defs.h"
#include "headers/pkt_cls_defs.h"
#include "headers/socket_defs.h"
#include "headers/upai_in6_defs.h"
#include "headers/vmlinux.h"

#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"
/* bpf_tracing.h (kprobe arg accessors) needs a target arch; mirror the
 * vmlinux.h fallback (x86) unless the build already selects one. */
#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm) && \
	!defined(__TARGET_ARCH_arm64) && !defined(__TARGET_ARCH_riscv) && \
	!defined(__TARGET_ARCH_loongarch) &&                              \
	!defined(__TARGET_ARCH_powerpc) && !defined(__TARGET_ARCH_s390) && \
	!defined(__TARGET_ARCH_mips)
#define __TARGET_ARCH_x86
#endif
#include "headers/bpf_tracing.h"
#include "ebpf_sync_defs.h"

// #define __DEBUG_ROUTING
// #define __PRINT_ROUTING_RESULT
// #define __PRINT_SETUP_PROCESS_CONNNECTION
// #define __DEBUG
// #define __UNROLL_ROUTE_LOOP

#ifndef __DEBUG
#undef bpf_printk
#define bpf_printk(...) ((void)0)
#endif
// #define likely(x) x
// #define unlikely(x) x
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)
// TC_ACT_UNSPEC and TCX_NEXT are both -1: the shared continuation action for
// classic cls_bpf and TCX multiprogram attachment.
#define DAE_TC_CONTINUE TC_ACT_UNSPEC
#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

#define IPV6_BYTE_LENGTH 16
#define TASK_COMM_LEN 16

#define PACKET_HOST 0
#define PACKET_OTHERHOST 3

#define NOWHERE_IFINDEX 0

#define MAX_INTERFACE_NUM 256
#ifndef MAX_MATCH_SET_LEN
#define MAX_MATCH_SET_LEN \
	(32 * 32) // Should be sync with common/consts/ebpf_sync_spec.json.
#endif
#define ROUTING_EPOCH_SLOT_NUM 2
#define ROUTING_EPOCH_SLOT_UNKNOWN 0
#define ROUTING_EPOCH_SLOT_RESULT_SHIFT 41
#define ROUTING_EPOCH_SLOT_RESULT_MASK 0x3
#define MAX_LPM_SIZE 2048000
#define MAX_LPM_NUM (ROUTING_EPOCH_SLOT_NUM * MAX_MATCH_SET_LEN + 8)
#define MAX_CONN_STATE_NUM (65536 * 4)
#define MAX_REDIRECT_TRACK_NUM 65536
// A reply binding (redirect_track entry) may only be rebound by a different
// publisher (interface/MAC) once it has been silent for this long. The window
// must be long enough that a roaming LAN client's gap (Wi-Fi roam, VM
// migration) does not freeze its binding, and short enough that a competing
// writer cannot hand a live flow's reply path to itself. Userspace injects
// EVENT_RATE.redirect_rebind_stale_ns; this is the clang-side fallback.
#define REDIRECT_REBIND_STALE_NS_FALLBACK 2000000000ULL
#define MAX_ROUTING_HANDOFF_NUM 65536
#define MAX_COOKIE_PID_PNAME_MAPPING_NUM 65536
#define MAX_DOMAIN_ROUTING_NUM 65536
// MAX_TCP_OFFLOAD_NUM bounds concurrent TCP relay offload sessions. Each
// session occupies two fast_sock entries (one per direction).
#define MAX_TCP_OFFLOAD_NUM 16384
#define MAX_ARG_LEN 128
#define IPV6_MAX_EXTENSIONS 8

#define ipv6_optlen(p) (((p)+1) << 3)

#define TPROXY_MARK 0x8000000

#define NDP_REDIRECT 137

// Param keys:
static const __u32 zero_key;
static const __u32 one_key = 1;
static const __u32 two_key = 2;

// Outbound Connectivity Map:

// Key format: outbound_id * 6 + domain * 2 + ipversion
// domain: 0=TCP, 1=DNS UDP, 2=data UDP; ipversion: 0=IPv4, 1=IPv6

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32); // true, false
	__uint(max_entries, 1536); // 256 outbounds * 3 domains * 2 ipversions
} outbound_connectivity_map SEC(".maps");

// Sockmap:
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key, __u32); // 0 is tcp4, 1 is udp, 2 is tcp6.
	__type(value, __u64); // fd of socket.
	__uint(max_entries, 3);
} listen_socket_map SEC(".maps");

union ip6 {
	__u8 u6_addr8[16];
	__be16 u6_addr16[8];
	__be32 u6_addr32[4];
	__be64 u6_addr64[2];
};

struct redirect_tuple {
	union ip6 sip;
	union ip6 dip;
};

struct redirect_entry {
	__u32 ifindex;
	__u8 smac[6];
	__u8 dmac[6];
	__u8 from_wan;
	__u8 padding[3];
	__u64 last_seen_ns;
};

// redirect_track: reply traffic routing; HASH with timestamp-based cleanup.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct redirect_tuple);
	__type(value, struct redirect_entry);
	__uint(max_entries, MAX_REDIRECT_TRACK_NUM);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} redirect_track SEC(".maps");

struct ip_port {
	union ip6 ip;
	__be16 port;
};

// routing_result: routing decision for userspace cache and first-packet handoff.
struct routing_result {
	__u32 mark;
	__u8 must;
	__u8 mac[6];
	__u8 outbound;
	__u8 pname[TASK_COMM_LEN];
	__u32 pid;
	__u8 dscp;
	// 0 is unknown; active routing slots 0 and 1 are encoded as 1 and 2.
	__u8 routing_epoch_slot;
	__u16 datapath_generation;
};

static __always_inline __u8 routing_epoch_slot_encode(__u32 slot)
{
	if (slot >= ROUTING_EPOCH_SLOT_NUM)
		return ROUTING_EPOCH_SLOT_UNKNOWN;
	return (__u8)(slot + 1);
}

static __always_inline __u8 routing_epoch_slot_sanitize(__u8 encoded_slot)
{
	return encoded_slot <= ROUTING_EPOCH_SLOT_NUM ? encoded_slot :
		ROUTING_EPOCH_SLOT_UNKNOWN;
}

static __always_inline __u8
routing_epoch_slot_from_route_result(__s64 route_result)
{
	return routing_epoch_slot_sanitize(
		(__u8)(((__u64)route_result >> ROUTING_EPOCH_SLOT_RESULT_SHIFT) &
		       ROUTING_EPOCH_SLOT_RESULT_MASK));
}

struct tuples_key {
	union ip6 sip;
	union ip6 dip;
	__u16 sport;
	__u16 dport;
	__u8 l4proto;
};

struct tuples {
	struct tuples_key five;
	__u8 dscp;
};

struct routing_handoff_entry {
	__u64 last_seen_ns;
	struct routing_result result;
};

struct dae_param {
	__u32 tproxy_port;
	__u32 control_plane_pid;
	__u32 dae0_ifindex;
	__u32 dae_netns_id;
	__u8 dae0peer_mac[6];
	__u8 padding_after_mac[2]; // pad to align use_redirect_peer
	__u8 use_redirect_peer;
	__u8 has_bpf_get_current_task;
	__u16 datapath_generation;
	// dae_socket_mark is set on dae's own sockets (Anyfrom pool) to identify them.
	// When bpf_sk_lookup_* finds a socket, we check this mark to skip dae's own sockets.
	// This prevents false positives in NAT loopback detection for transparent proxying.
	__u32 dae_socket_mark;
};

/* Use const volatile for cilium/ebpf v0.20.0 compatibility.
 * This ensures the variable is placed in .rodata section and
 * can be rewritten from userspace via RewriteConstants. */
const volatile struct dae_param PARAM = {};

/* dae_ifindex_map holds the runtime-updatable ifindex of the dae0 device.
 * Unlike PARAM.dae0_ifindex (frozen in .rodata at load time), this ARRAY map
 * can be updated from userspace without reloading the BPF program. This allows
 * hot-recovery when the kernel recreates the netkit/veth device and assigns a
 * new ifindex. BPF falls back to PARAM.dae0_ifindex if the map is uninitialized.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} dae_ifindex_map SEC(".maps");

/* fast_sock holds the two sockets of every user-space offloaded TCP relay
 * pair. The Go control plane registers each socket under its reversed
 * four-tuple (sip=remote, dip=local, sport=remote_port, dport=local_port),
 * pointing at the peer socket's fd. The sk_skb stream-verdict program
 * tcp_offload_redirect then splices received data between the pair in-kernel.
 * Sockets are automatically deleted from the map once closed.
 */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct tuples_key);
	__type(value, __u64);
	__uint(max_entries, MAX_TCP_OFFLOAD_NUM * 2);
} fast_sock SEC(".maps");

/* tcp_offload_pause is the backlog fuse: while a key is present, the
 * stream-verdict program passes received data through (SK_PASS) instead of
 * redirecting, so the userspace fallback forwards it while the kernel drains
 * skbs already queued on the peer's egress retry path. Unlike deleting the
 * fast_sock entry, a pause does not tear down the psock (which would drop
 * the queued skbs); the Go side removes the key once the backlog drains.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct tuples_key);
	__type(value, __u8);
	__uint(max_entries, MAX_TCP_OFFLOAD_NUM * 2);
} tcp_offload_pause SEC(".maps");

/* tcp_offload_sent counts bytes that skb_send_sock delivered to a socket's
 * send path, keyed by the skb's reversed four-tuple (the same key space as
 * fast_sock and tcp_offload_pause). The Go session compares it against
 * tcp_info receive deltas to compute the egress retry-queue backlog that
 * drives the pause fuse.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct tuples_key);
	__type(value, __u64);
	__uint(max_entries, MAX_TCP_OFFLOAD_NUM * 2);
} tcp_offload_sent SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct tuples_key);
	__type(value, struct routing_handoff_entry);
	__uint(max_entries, MAX_ROUTING_HANDOFF_NUM);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} routing_handoff_map SEC(".maps");

// Array of LPM tries:
struct lpm_key {
	/* Keep the LPM trie header layout local to avoid unnecessary CO-RE
	 * relocations against struct bpf_lpm_trie_key. The map ABI only
	 * requires prefixlen to be the first u32 in the key. */
	__u32 prefixlen;
	__be32 data[4];
};

struct map_lpm_type {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, MAX_LPM_SIZE);
	__uint(key_size, sizeof(struct lpm_key));
	__uint(value_size, sizeof(__u32));
} unused_lpm_type SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, MAX_LPM_NUM);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
	__array(values, struct map_lpm_type);
} lpm_array_map SEC(".maps");

struct port_range {
	__u16 port_start;
	__u16 port_end;
};

/*
 * Rule is like as following:
 *
 * domain(geosite:cn, suffix: google.com) && l4proto(tcp) -> my_group
 *
 * pseudocode: domain(geosite:cn || suffix:google.com) && l4proto(tcp) ->
 * my_group
 *
 * A match_set can be: IP set geosite:cn, suffix google.com, tcp proto
 */
struct match_set {
	union {
		__u8 __value[16]; // Placeholder for bpf2go.

		__u32 index;
		struct port_range port_range;
		enum L4ProtoType l4proto_type;
		enum IpVersionType ip_version;
		__u32 pname[TASK_COMM_LEN / 4];
		__u8 dscp;
	};
	__u8 not; // Subrule inversion flag.
	enum MatchType type;
	__u8 outbound; // User-defined value range is [0, 252].
	__u8 must;
	__u32 mark;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct match_set);
	__uint(max_entries, ROUTING_EPOCH_SLOT_NUM * MAX_MATCH_SET_LEN);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} routing_map SEC(".maps");

// Each slot holds the active routing rules length for that epoch.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, ROUTING_EPOCH_SLOT_NUM);
} routing_meta_map SEC(".maps");

// key=0: active routing epoch slot. The zero-initialized value selects slot 0.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} active_routing_epoch_map SEC(".maps");

struct domain_routing {
	__u32 bitmap[MAX_MATCH_SET_LEN / 32];
};

struct routing_epoch_ip {
	__u32 slot;
	__be32 addr[4];
};

// domain_routing_map: epoch+address → routing bitmap cache (HASH, no LRU).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct routing_epoch_ip);
	__type(value, struct domain_routing);
	__uint(max_entries, ROUTING_EPOCH_SLOT_NUM * MAX_DOMAIN_ROUTING_NUM);
} domain_routing_map SEC(".maps");

struct ip_port_proto {
	__u32 ip[4];
	__be16 port;
	__u8 proto;
};

struct pid_pname {
	__u64 last_seen_ns;
	__u32 pid;
	char pname[TASK_COMM_LEN];
};

#define COOKIE_PID_UPDATE_INTERVAL_NS 1000000000ULL  // 1 second

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct pid_pname);
	__uint(max_entries, MAX_COOKIE_PID_PNAME_MAPPING_NUM);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cookie_pid_map SEC(".maps");

// conn_state: shared TCP/UDP connection state with embedded routing.
union routing_meta {
	struct {
		__u32 mark;
		__u8 outbound;
		__u8 must;
		__u8 dscp;
		__u8 has_routing;
	} data;
	__u64 raw;
} __attribute__((aligned(8)));

static __always_inline union routing_meta
build_routing_meta(__u8 outbound, __u32 mark, __u8 must, __u8 dscp)
{
	union routing_meta meta = { 0 };

	meta.data.outbound = outbound;
	meta.data.mark = mark;
	meta.data.must = must;
	meta.data.dscp = dscp;
	meta.data.has_routing = 1;
	return meta;
}

static __always_inline void
publish_routing_meta(union routing_meta *dst, union routing_meta meta)
{
	/* Publish routing only after side fields (mac/pname/pid) are ready.
	 *
	 * barrier() is a COMPILER-ONLY fence: it orders the generated machine
	 * code but emits no CPU fence, so the store-release guarantee is
	 * architecture-dependent. On strongly ordered targets (x86 TSO) the
	 * prior writes to mac/pname/pid are observed before has_routing=1.
	 * On weakly ordered targets a reader that observes has_routing=1 may
	 * briefly read stale side fields. This is an accepted trade-off: the
	 * side fields are advisory per-flow metadata consumed through the
	 * conn_state cache domain, the window is a single first-packet
	 * publication, and a full __sync_synchronize() fence in this hot path
	 * would need verification across the whole kernel matrix before it
	 * could be considered.
	 */
	barrier();
	*(volatile __u64 *)&dst->raw = meta.raw;
}

static __always_inline bool bpf_sock_is_dae_socket(const struct bpf_sock *sk)
{
	if (!sk || !PARAM.dae_socket_mark)
		return false;

	struct bpf_sock *fullsock = bpf_sk_fullsock((struct bpf_sock *)sk);

	return fullsock && fullsock->mark == PARAM.dae_socket_mark;
}

/* Whether the matched host socket is bound to the packet's exact destination
 * address. A wildcard-bound socket (bound address zero) answers for every
 * destination, so its presence says nothing about whether the packet was
 * addressed to this host; only an exact match is proof that the packet is
 * addressed to a service this host runs. */
static __always_inline bool
sock_bound_to_daddr(const struct bpf_sock *sk, const struct tuples *tuples,
		    __be16 h_proto)
{
	if (h_proto == bpf_htons(ETH_P_IP)) {
		__u32 bound = sk->src_ip4; // inet_rcv_saddr, 0 == wildcard

		return bound != 0 && bound == tuples->five.dip.u6_addr32[3];
	}

	if (h_proto == bpf_htons(ETH_P_IPV6)) {
		const __u32 *bound = sk->src_ip6;
		bool wildcard = !(bound[0] | bound[1] | bound[2] | bound[3]);

		return !wildcard &&
		       bound[0] == tuples->five.dip.u6_addr32[0] &&
		       bound[1] == tuples->five.dip.u6_addr32[1] &&
		       bound[2] == tuples->five.dip.u6_addr32[2] &&
		       bound[3] == tuples->five.dip.u6_addr32[3];
	}

	return false;
}

struct conn_state {
	// For each flow (echo symmetric path), note the original flow direction.
	// Mark as true if traffic go through wan ingress.
	// For traffic from lan that go through wan ingress, dae parse them in lan egress
	bool is_wan_ingress_direction;

	// TCP state. UDP entries leave this as TCP_STATE_ACTIVE.
	__u8 state;

	// Last seen timestamp in nanoseconds (bpf_ktime_get_ns).
	// Userspace janitor periodically cleans up expired entries by protocol.
	__u64 last_seen_ns;

	// Embedded routing decision result for this flow.
	// This avoids a separate routing_tuples_map lookup and ensures consistency.
	union routing_meta meta;
	__u8 mac[6];               // Next hop MAC for redirected packets
	__u8 padding[2];           // Alignment
	__u8 pname[TASK_COMM_LEN]; // Process name (for WAN egress; empty for LAN)
	__u32 pid;                 // Process ID (for WAN egress; 0 for LAN)
	// 0 is unknown; active routing slots 0 and 1 are encoded as 1 and 2.
	__u8 routing_epoch_slot;
	__u8 padding_after_pid;
	__u16 datapath_generation;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CONN_STATE_NUM);
	__type(key, struct tuples_key);
	__type(value, struct conn_state);
	__uint(pinning, LIBBPF_PIN_BY_NAME);  // Loader may override pinning on cold start.
	__uint(map_flags, BPF_F_NO_PREALLOC);
} conn_state_map SEC(".maps");

enum bpf_stats_key {
	// key=0: UDP conn state map overflow count (drives janitor pressure).
	BPF_STATS_UDP_CONN_OVERFLOW = 0,
	// key=1: TCP conn state map overflow count (drives janitor pressure).
	BPF_STATS_TCP_CONN_OVERFLOW = 1,
	// key=2: redirect_track update rejected because the HASH is full.
	BPF_STATS_REDIRECT_OVERFLOW = 2,
	// key=3: redirect_track update failed for a reason other than a full map.
	BPF_STATS_REDIRECT_UPDATE_FAILED = 3,
	// key=4: reply binding kept because a different publisher raced a fresh
	// entry (see publish_redirect_track_for_packet).
	BPF_STATS_REDIRECT_REBIND_REJECTED = 4,
	// key=5: pure SYN refused to rewrite an ACTIVE flow's routing metadata.
	BPF_STATS_SYN_REBIND_REJECTED = 5,
	// key=6: established TCP forwarded without any cached routing decision
	// (e.g. flows that predate a restart). Visibility only, no policy change.
	BPF_STATS_STATELESS_TCP_PASSTHROUGH = 6,
	// key=7: non-initial fragment forwarded without routing. Visibility only:
	// dropping fragments is a separate policy decision.
	BPF_STATS_FRAG_TAIL_PASSED = 7,
	// key=8: packet whose IP header parsed but whose L4 protocol is not
	// TCP/UDP, forwarded without routing.
	BPF_STATS_PARSE_UNSUPPORTED_L4 = 8,
	// key=9: WAN-ingress UDP packet whose flow had no forward state yet (an
	// unsolicited inbound flow). Observability only: the state is still
	// created, because the is_wan_ingress_direction marker it carries is
	// what keeps host-terminated UDP replies on the pass-through path.
	BPF_STATS_UNSOLICITED_UDP_SEEN = 9,
	// key=10: pid_is_control_plane fell back to the reserved-mark bit test
	// because no so_mark was injected into PARAM.
	BPF_STATS_SOCKMARK_FALLBACK = 10,
	// key=11: datapath events dropped because the ringbuf had no room. The
	// consumers are advisory, but a dropped event must never be invisible.
	BPF_STATS_EVENT_DROP = 11,
	// key=12: pure SYN on a live ACTIVE flow whose cached routing belongs to
	// a different routing epoch or datapath generation. The entry is
	// re-created from the current generation instead of being locked, so a
	// connection that outlives a reload ends up on the current rules.
	BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE = 12,
	BPF_STATS_MAX = 13,
};

// Per-packet datapath counters, indexed by enum bpf_stats_key. Userspace reads
// them on the janitor tick (readMapOverflowCounters / checkBpfMapHealth); the
// pre-existing conn-state overflow keys additionally drive the janitor's
// pressure mode. Keys are a userspace-visible contract: mirror any change in
// control/event_rate_contract.go (guarded by
// TestBpfStatsKeysParityWithKernelSource).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, BPF_STATS_MAX);
} bpf_stats_map SEC(".maps");

// bump_stat increments a datapath counter. The ARRAY map cannot fail its
// lookup for an in-range key, but keep the NULL check: a silent miss here is
// exactly the kind of invisible degradation these counters exist to remove.
static __always_inline void bump_stat(__u32 key)
{
	__u64 *counter = bpf_map_lookup_elem(&bpf_stats_map, &key);

	if (counter)
		__sync_fetch_and_add(counter, 1);
}

// Event rate-limit constants are owned by userspace and injected through the
// .rodata datasec at load time (same mechanism as struct dae_param). The
// initializers below are clang-side fallbacks: Go overwrites the variable
// before LoadAndAssign, and the ARRAY capacity is derived from the same
// userspace key there, so the key-domain/capacity pairing has a single
// owner instead of a two-sided convention.
struct dae_event_rate {
	__u64 window_ns;                // per-key minimum spacing between emissions
	__u64 redirect_rebind_stale_ns; // reply-binding freeze window
	__u32 blocked_key;              // reserved rate key for DAE_EVENT_BLOCKED
	__u32 redirect_rebind_key;      // ... DAE_EVENT_REDIRECT_REBIND_REJECTED
	__u32 overflow_key;             // ... the conn-state/map overflow events
	__u32 syn_rebind_key;           // ... DAE_EVENT_SYN_REBIND_REJECTED
	// stateless_tcp_key and frag_tail_key are reserved: the two event types
	// they throttled (6 and 7) are no longer emitted, because a by-design
	// passthrough must not warn per event. They stay in place so the .rodata
	// layout, the ARRAY capacity derived from the highest key, and the
	// userspace mirror (eventRateSpec in control/event_rate_contract.go) stay
	// byte-identical.
	__u32 stateless_tcp_key;        // reserved: DAE_EVENT_RESERVED_* (6)
	__u32 frag_tail_key;            // reserved: DAE_EVENT_RESERVED_* (7)
	// Explicit padding: the Go mirror is written with packed binary encoding,
	// so the C layout must not carry implicit alignment holes either.
	__u32 padding[2];
};

// window_ns first keeps the struct free of implicit padding.
const volatile struct dae_event_rate EVENT_RATE = {
	.window_ns = 1000000000ULL,
	.redirect_rebind_stale_ns = REDIRECT_REBIND_STALE_NS_FALLBACK,
	.blocked_key = 256,
	.redirect_rebind_key = 257,
	.overflow_key = 258,
	.syn_rebind_key = 259,
	.stateless_tcp_key = 260,
	.frag_tail_key = 261,
};

// Map definitions need an integer constant expression for max_entries, so
// the fallback stays a macro; the authoritative capacity is re-derived from
// the injected EVENT_RATE keys on the Go side (tuneEventRateMap).
#define EVENT_RATE_KEY_MAX_FALLBACK 261

// alive_block_rate_map rate-limits event emission: key = outbound id for
// DAE_EVENT_BLOCKED_ALIVE, or one of the reserved EVENT_RATE keys beyond the
// 0..255 outbound domain for the datapath-wide event types; value = last
// emission time (CLOCK_MONOTONIC ns). Without this, an outbound that is not
// alive (or a blocked-flow / overflow / rebind flood) would emit one event per
// packet and flood the ringbuf, starving the consumed event types. Key domains
// cannot collide: outbound ids live in the 0..255 u8 domain while the reserved
// keys start at 256.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, EVENT_RATE_KEY_MAX_FALLBACK + 1);
} alive_block_rate_map SEC(".maps");

// Events delivered to userspace via ring buffer.
enum dae_event_type {
	DAE_EVENT_BLOCKED = 0,       // Connection blocked (OUTBOUND_BLOCK)
	DAE_EVENT_UDP_CONN_OVERFLOW = 1, // UDP conn state map overflow
	DAE_EVENT_TCP_CONN_OVERFLOW = 2, // TCP conn state map overflow
	DAE_EVENT_BLOCKED_ALIVE = 3, // Connection blocked (outbound not alive)
	// A different publisher tried to steal a fresh reply binding.
	DAE_EVENT_REDIRECT_REBIND_REJECTED = 4,
	// A pure SYN was refused rewrite of an ACTIVE flow's routing.
	DAE_EVENT_SYN_REBIND_REJECTED = 5,
	// Reserved, never emitted: established TCP forwarded without a
	// cached routing decision is the normal state of every pre-existing flow
	// after a restart, so it is counted per packet
	// (BPF_STATS_STATELESS_TCP_PASSTHROUGH) and summarised by userspace on the
	// health tick instead of warning per event. The number stays reserved so
	// the remaining types keep their wire values.
	DAE_EVENT_RESERVED_STATELESS_TCP_PASSTHROUGH = 6,
	// Reserved, never emitted: forwarding a non-initial fragment is the
	// intended policy and it is counted per packet
	// (BPF_STATS_FRAG_TAIL_PASSED). The tuple such an event could carry has no
	// L4 header to read either: the parser returns before L4 parsing
	// (parse_transport_fast), so its ports are scratch values, not wire data.
	DAE_EVENT_RESERVED_FRAG_TAIL_PASSED = 7,
	// redirect_track could not store a reply binding. The matching
	// bpf_stats_map key separates "map full" from "update failed".
	DAE_EVENT_REDIRECT_UPDATE_FAILED = 8,
	// A pure SYN on a live flow was re-routed because the flow's cached
	// routing belonged to a different routing epoch or datapath generation.
	DAE_EVENT_SYN_REBIND_REROUTED = 9,
};

struct dae_event {
	__u64 timestamp;
	__u32 type;
	__u32 pid;
	__u8 pname[16];
	__u8 outbound;
	__u8 l4proto;
	__u8 pad[2];
	__u32 sip[4];
	__u32 dip[4];
	__u16 sport;
	__u16 dport;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);  // 256KB ring buffer
} event_ringbuf SEC(".maps");

// TCP connection state constants.
enum tcp_state {
	TCP_STATE_ACTIVE = 0,
	TCP_STATE_CLOSING = 1,  // FIN or RST seen
};

// Parsed header state; lives in per-CPU scratch map to stay under 512-byte stack.
struct parse_transport_ctx {
	struct ethhdr ethh;
	struct iphdr iph;
	struct ipv6hdr ipv6h;
	struct icmp6hdr icmp6h;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 ihl;
	__u8 l4proto;
	__u8 listener_l4proto;
	__u8 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct parse_transport_ctx);
	__uint(max_entries, 1);
} parse_ctx_scratch_map SEC(".maps");

// Functions:

/* Reserves the ringbuf record instead of building it on the BPF stack: the
 * 72-byte event would otherwise be charged to every caller's frame, and the
 * datapath call chains must stay inside the 512-byte combined stack budget.
 * Fields that have no source are zeroed explicitly (a reserved record is not
 * pre-zeroed), and a failed reservation drops the event exactly like the
 * previous bpf_ringbuf_output() on a full ring. */
static __always_inline int
send_dae_event(__u32 type, __u32 pid, const char *pname, bool pname_valid,
	       __u8 outbound, __u8 l4proto, const __u32 *sip,
	       const __u32 *dip, __u16 sport, __u16 dport)
{
	struct dae_event *e = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*e), 0);

	if (!e) {
		/* The ringbuf is full. The event is lost either way (this is
		 * what bpf_ringbuf_output() did before), but the loss must be
		 * countable: userspace raises this to the operator. */
		bump_stat(BPF_STATS_EVENT_DROP);
		return -1;
	}

	e->timestamp = bpf_ktime_get_ns();
	e->type = type;
	e->pid = pid;
	e->outbound = outbound;
	e->l4proto = l4proto;
	e->sport = sport;
	e->dport = dport;
	__builtin_memset(e->pname, 0, sizeof(e->pname));
	__builtin_memset(e->sip, 0, sizeof(e->sip));
	__builtin_memset(e->dip, 0, sizeof(e->dip));

	/* The copy is guarded by a scalar flag, not by `pname != NULL`: clang
	 * 15/16/17 lower a select of a pointer and NULL (`c ? p : NULL`) into a
	 * bitwise AND on a pointer register, which the verifier rejects with
	 * "bitwise operator &= on pointer prohibited". Passing a pointer that is
	 * always valid (the conntrack args slot) plus this flag keeps the select
	 * on a scalar. */
	if (pname_valid)
		__builtin_memcpy(e->pname, pname, 16);

	if (sip)
		__builtin_memcpy(e->sip, sip, 16);

	if (dip)
		__builtin_memcpy(e->dip, dip, 16);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// blocked_event_rate_limited reports whether an emission for rate key
// is allowed (at most once per second per key across CPUs). The clock is
// sampled AFTER the previous-emission read so now >= old always holds for
// the value compared: sampling first lets a concurrent CPU claim the slot
// with a newer timestamp between the sample and the read, and the unsigned
// subtraction then underflows past the 1s window. CAS claims the slot
// atomically: when several CPUs observe an expired window concurrently,
// only the CAS winner emits and the others are rate-limited, keeping the
// per-key budget strict instead of merely best-effort.
static __always_inline bool
blocked_event_rate_limited(__u32 key)
{
	__u64 *last = bpf_map_lookup_elem(&alive_block_rate_map, &key);

	if (!last)
		return true;

	__u64 old = *last;
	__u64 now = bpf_ktime_get_ns();

	if (now - old < EVENT_RATE.window_ns)
		return true;
	if (__sync_val_compare_and_swap(last, old, now) != old)
		return true;
	return false;
}

// send_blocked_alive_event emits DAE_EVENT_BLOCKED_ALIVE at most once per
// second per outbound. The rate limit keeps a dead outbound from flooding the
// ringbuf with one event per blocked packet while the periodic health check is
// still recovering it. Returns true when an event was actually emitted.
static __always_inline bool
send_blocked_alive_event(__u8 outbound, __u8 l4proto, const __u32 *sip,
			 const __u32 *dip, __u16 sport, __u16 dport)
{
	if (blocked_event_rate_limited((__u32)outbound))
		return false;

	send_dae_event(DAE_EVENT_BLOCKED_ALIVE, 0, NULL, false, outbound, l4proto,
		       sip, dip, sport, dport);
	return true;
}

// send_blocked_event emits DAE_EVENT_BLOCKED (type 0) at most once per
// second. The event has no userspace consumer today, and an unthrottled
// blocked-flow flood (e.g. an attacker hitting a block rule at line rate)
// would occupy ringbuf space that the consumed event types (1/2/3) need.
static __always_inline void
send_blocked_event(__u8 outbound, __u8 l4proto, const __u32 *sip,
		   const __u32 *dip, __u16 sport, __u16 dport)
{
	if (blocked_event_rate_limited(EVENT_RATE.blocked_key))
		return;

	send_dae_event(DAE_EVENT_BLOCKED, 0, NULL, false, outbound, l4proto, sip,
		       dip, sport, dport);
}

// send_anomaly_event emits a datapath anomaly at most once per second per
// reserved rate key. The bpf_stats_map counter for the same condition always
// advances per occurrence; this call only bounds the ringbuf cost of a flood.
// key may be NULL when the packet was never classified (e.g. a non-IP frame).
//
// The rate key is per event type, not per flow: every flow of the type shares
// one 1s budget, so this bounds the emission rate but says nothing about how
// many flows are affected, and the tuple it reports is one arbitrary sample.
// Only use it for a genuine anomaly. A path that is the normal steady state
// (established TCP without cached routing after a restart, a forwarded
// fragment tail) must count per packet with bump_stat instead and let
// userspace summarise the counter's interval delta, or the log carries one
// warning per second for as long as the state lasts.
static __always_inline void
send_anomaly_event(__u32 rate_key, __u32 type, __u8 l4proto,
		   const struct tuples_key *key)
{
	if (blocked_event_rate_limited(rate_key))
		return;

	if (key)
		send_dae_event(type, 0, NULL, false, 0, l4proto, key->sip.u6_addr32,
			       key->dip.u6_addr32, key->sport, key->dport);
	else
		send_dae_event(type, 0, NULL, false, 0, l4proto, NULL, NULL, 0, 0);
}

static __always_inline __u8 ipv4_get_dscp(const struct iphdr *iph)
{
	return (iph->tos & 0xfc) >> 2;
}

/* Raw-byte accessors for the UAPI header bitfields.
 *
 * struct iphdr/struct tcphdr declare ihl/version and doff/fin/syn/rst/... as
 * bitfields whose allocation order follows the target's endianness, not the
 * wire format: on a big-endian build `iph->ihl` reads the version nibble and
 * `tcph->syn` reads a different bit than the wire SYN bit, so every packet
 * classification below would be wrong (IPv4 dropped as malformed, IPv6 TCP
 * policy bypassed). Reading the header bytes directly keeps the datapath
 * identical on little- and big-endian builds, exactly like ipv6_get_dscp
 * above. The TCP flag masks are the wire-format values, which coincide with
 * the little-endian bitfield layout.
 */
static __always_inline __u8 iphdr_ihl(const void *p)
{
	return ((const __u8 *)p)[0] & 0x0f;
}

static __always_inline __u8 iphdr_version(const void *p)
{
	return ((const __u8 *)p)[0] >> 4;
}

static __always_inline __u8 tcph_doff(const void *p)
{
	return ((const __u8 *)p)[12] >> 4;
}

static __always_inline __u8 tcph_flags(const void *p)
{
	return ((const __u8 *)p)[13];
}

#define TCPH_FIN 0x01
#define TCPH_SYN 0x02
#define TCPH_RST 0x04
#define TCPH_ACK 0x10

static __always_inline __u8 ipv6_get_dscp(const struct ipv6hdr *ipv6h)
{
	const __u8 *version_and_tc = (const __u8 *)ipv6h;

	/* Read DSCP from raw bytes to avoid bitfield layout variability. */
	return ((version_and_tc[0] & 0x0f) << 2) | (version_and_tc[1] >> 6);
}

static __always_inline void
get_tuples(const struct __sk_buff *skb, struct tuples *tuples,
	   const struct iphdr *iph, const struct ipv6hdr *ipv6h,
	   const struct tcphdr *tcph, const struct udphdr *udph, __u8 l4proto)
{
	__builtin_memset(tuples, 0, sizeof(*tuples));
	tuples->five.l4proto = l4proto;

	// Read the version/ihl byte raw, then classify; iph is a stack copy of
	// the header and both branches below use raw-byte helpers.
	if (iphdr_version(iph) == 4) {
		tuples->five.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuples->five.sip.u6_addr32[3] = iph->saddr;

		tuples->five.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuples->five.dip.u6_addr32[3] = iph->daddr;

		tuples->dscp = ipv4_get_dscp(iph);

	} else {
		// IPv6
		__builtin_memcpy(&tuples->five.dip, &ipv6h->daddr,
				 IPV6_BYTE_LENGTH);
		__builtin_memcpy(&tuples->five.sip, &ipv6h->saddr,
				 IPV6_BYTE_LENGTH);

		tuples->dscp = ipv6_get_dscp(ipv6h);
	}
	if (l4proto == IPPROTO_TCP && tcph) {
		tuples->five.sport = tcph->source;
		tuples->five.dport = tcph->dest;
	} else if (udph) {
		tuples->five.sport = udph->source;
		tuples->five.dport = udph->dest;
	}
}

static __always_inline bool equal16(const __be32 x[4], const __be32 y[4])
{
	return ((__be64 *)x)[0] == ((__be64 *)y)[0] &&
	       ((__be64 *)x)[1] == ((__be64 *)y)[1];
}

static __always_inline bool is_extension_header(__u8 nexthdr)
{
	switch (nexthdr) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
	case IPPROTO_DSTOPTS:
	case IPPROTO_AH:
	case IPPROTO_MH:
		return true;
	default:
		return false;
	}
}

/* Total length in bytes of a walkable IPv6 extension header. AH (RFC 4302)
 * encodes its length in 4-octet units excluding the first 8 octets:
 * (payload_len + 2) * 4. Every other extension header (incl. MH) uses
 * 8-octet units, which is what ipv6_optlen computes.
 */
static __always_inline __u32 ipv6_exthdr_len(__u8 nexthdr, __u8 len_field)
{
	if (nexthdr == IPPROTO_AH)
		return (__u32)(len_field + 2) * 4;
	return ipv6_optlen(len_field);
}

/* Parser return codes. Positive values mean "not classifiable here" and are
 * forwarded unchanged by every caller; negative values are malformed packets.
 * PARSE_UNSUPPORTED_L4 and PARSE_UNSUPPORTED_ETH are deliberately distinct so
 * the consumers can tell "the IP header parsed but the L4 protocol is not
 * routed" (counted as BPF_STATS_PARSE_UNSUPPORTED_L4) from "this frame is not
 * IP at all" without changing the forwarding decision.
 */
#define PARSE_FRAGMENT 2
#define PARSE_UNSUPPORTED_L4 3
#define PARSE_UNSUPPORTED_ETH 4

static __always_inline __u8
tcp_listener_l4proto(const struct tcphdr *tcph)
{
	__u8 flags;

	if (!tcph)
		return 0;
	flags = tcph_flags(tcph);
	return (flags & TCPH_SYN) && !(flags & TCPH_ACK) ? IPPROTO_TCP : 0;
}

// report_parse_passthrough accounts for a packet the parser could not
// classify, right before the caller forwards it unchanged. The forwarding
// decision itself is intentionally untouched here: dropping non-initial
// fragments or non-TCP/UDP traffic is a policy decision tracked apart from
// this visibility work.
static __always_inline void
report_parse_passthrough(int ret)
{
	if (ret == PARSE_FRAGMENT) {
		/* Forwarding a non-initial fragment is the intended policy,
		 * not an anomaly: only the counter is advanced here. The
		 * per-event warning this used to emit shared one 1s budget
		 * across every fragmenting flow in the datapath, so a
		 * steadily fragmenting path logged one line per second
		 * forever, while the tuple it carried said nothing the
		 * operator could act on. Userspace reports the counter's
		 * interval delta instead (see reportDatapathPassthroughSummary
		 * in control/control_plane.go). */
		bump_stat(BPF_STATS_FRAG_TAIL_PASSED);
	} else if (ret == PARSE_UNSUPPORTED_L4) {
		bump_stat(BPF_STATS_PARSE_UNSUPPORTED_L4);
	}
}

// Fast-path packet parsing via bpf_skb_pull_data + direct access.
// Returns 0 on success, -1 for slow-path fallback, -EFAULT for malformed.
static __always_inline int
parse_transport_fast(struct __sk_buff *skb, __u32 link_h_len,
		     struct parse_transport_ctx *ctx)
{
	struct ethhdr *ethh = &ctx->ethh;
	struct iphdr *iph = &ctx->iph;
	struct ipv6hdr *ipv6h = &ctx->ipv6h;
	struct icmp6hdr *icmp6h = &ctx->icmp6h;
	struct tcphdr *tcph = &ctx->tcph;
	struct udphdr *udph = &ctx->udph;
	__u8 *ihl = &ctx->ihl;
	__u8 *l4proto = &ctx->l4proto;
	__u8 *listener_l4proto = &ctx->listener_l4proto;

	void *data, *data_end;
	__u32 offset = 0;

	*ihl = 0;
	*l4proto = 0;
	*listener_l4proto = 0;
	__builtin_memset(ethh, 0, sizeof(struct ethhdr));
	__builtin_memset(iph, 0, sizeof(struct iphdr));
	__builtin_memset(ipv6h, 0, sizeof(struct ipv6hdr));
	__builtin_memset(icmp6h, 0, sizeof(struct icmp6hdr));
	__builtin_memset(tcph, 0, sizeof(struct tcphdr));
	__builtin_memset(udph, 0, sizeof(struct udphdr));

	// Pull 128 bytes: eth(14)+IP(20)+TCP(20)+options. Larger sizes hurt verifier.
#define HEADER_PULL_SIZE 128
	if (bpf_skb_pull_data(skb, HEADER_PULL_SIZE))
		return -1;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	// Parse Ethernet header (or L3-only)
	if (link_h_len == ETH_HLEN) {
		struct ethhdr *eth_ptr = data;

		if ((void *)(eth_ptr + 1) > data_end)
			return -1;

		ethh->h_proto = eth_ptr->h_proto;
		ethh->h_dest[0] = eth_ptr->h_dest[0];
		ethh->h_dest[1] = eth_ptr->h_dest[1];
		ethh->h_dest[2] = eth_ptr->h_dest[2];
		ethh->h_dest[3] = eth_ptr->h_dest[3];
		ethh->h_dest[4] = eth_ptr->h_dest[4];
		ethh->h_dest[5] = eth_ptr->h_dest[5];
		ethh->h_source[0] = eth_ptr->h_source[0];
		ethh->h_source[1] = eth_ptr->h_source[1];
		ethh->h_source[2] = eth_ptr->h_source[2];
		ethh->h_source[3] = eth_ptr->h_source[3];
		ethh->h_source[4] = eth_ptr->h_source[4];
		ethh->h_source[5] = eth_ptr->h_source[5];
		offset += sizeof(struct ethhdr);
	} else {
		ethh->h_proto = skb->protocol;
	}

	// Parse IP header
	if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph_ptr = data + offset;

		if ((void *)(iph_ptr + 1) > data_end)
			return -1;
		// Malformed IP header: ihl < 5 is invalid, no point falling back
		if (iphdr_ihl(iph_ptr) < 5)
			return -EFAULT;

		// Copy saddr/daddr early so get_tuples works for PARSE_FRAGMENT.
		// The version/ihl byte is copied raw: the UAPI bitfields cannot be
		// trusted on big-endian targets.
		((__u8 *)iph)[0] = ((const __u8 *)iph_ptr)[0];
		iph->tos = iph_ptr->tos;
		iph->protocol = iph_ptr->protocol;
		iph->saddr = iph_ptr->saddr;
		iph->daddr = iph_ptr->daddr;
		*ihl = iphdr_ihl(iph_ptr);
		*l4proto = iph_ptr->protocol;

		__u32 ip_hdr_len = iphdr_ihl(iph_ptr) * 4;
		__u32 l4_offset = offset + ip_hdr_len;

		// First fragment carries L4 header; non-initial fragments fall back.
		__u16 frag_off = bpf_ntohs(iph_ptr->frag_off);

		if ((frag_off & 0x1FFF) != 0)
			return PARSE_FRAGMENT;

		switch (iph->protocol) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph_ptr = data + l4_offset;

			if ((void *)(tcph_ptr + 1) > data_end)
				return -1;
			tcph->source = tcph_ptr->source;
			tcph->dest = tcph_ptr->dest;
			tcph->seq = tcph_ptr->seq;
			tcph->ack_seq = tcph_ptr->ack_seq;
			// Data offset + flags, read through the raw accessors for
			// the same reason as the IP version/ihl byte above. The
			// reserved nibble is zero in a valid header and is not read
			// by any consumer of the copied struct.
			((__u8 *)tcph)[12] = tcph_doff(tcph_ptr) << 4;
			((__u8 *)tcph)[13] = tcph_flags(tcph_ptr);
			tcph->window = tcph_ptr->window;
			*listener_l4proto = tcp_listener_l4proto(tcph_ptr);
			return 0;
		}
		case IPPROTO_UDP: {
			struct udphdr *udph_ptr = data + l4_offset;

			if ((void *)(udph_ptr + 1) > data_end)
				return -1;
			udph->source = udph_ptr->source;
			udph->dest = udph_ptr->dest;
			udph->len = udph_ptr->len;
			udph->check = udph_ptr->check;
			*listener_l4proto = IPPROTO_UDP;
			return 0;
		}
		default:
			return PARSE_UNSUPPORTED_L4;
		}
	}

	if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6h_ptr = data + offset;

		if ((void *)(ipv6h_ptr + 1) > data_end)
			return -1;

		/* Preserve version, traffic class, and flow label for DSCP extraction. */
		__builtin_memcpy(ipv6h, ipv6h_ptr, 4);
		ipv6h->nexthdr = ipv6h_ptr->nexthdr;
		ipv6h->payload_len = ipv6h_ptr->payload_len;
		__u32 *saddr_dst = (__u32 *)ipv6h->saddr.in6_u.u6_addr32;
		const __u32 *saddr_src = (const __u32 *)ipv6h_ptr->saddr.in6_u.u6_addr32;

		saddr_dst[0] = saddr_src[0];
		saddr_dst[1] = saddr_src[1];
		saddr_dst[2] = saddr_src[2];
		saddr_dst[3] = saddr_src[3];
		__u32 *daddr_dst = (__u32 *)ipv6h->daddr.in6_u.u6_addr32;
		const __u32 *daddr_src = (const __u32 *)ipv6h_ptr->daddr.in6_u.u6_addr32;

		daddr_dst[0] = daddr_src[0];
		daddr_dst[1] = daddr_src[1];
		daddr_dst[2] = daddr_src[2];
		daddr_dst[3] = daddr_src[3];

		*l4proto = ipv6h_ptr->nexthdr;
		*ihl = sizeof(struct ipv6hdr) / 4;
		offset += sizeof(struct ipv6hdr);

		__u8 nexthdr = ipv6h_ptr->nexthdr;
		const __u8 *ext_hdr;

		for (int i = 0; i < IPV6_MAX_EXTENSIONS; i++) {
			if (nexthdr == IPPROTO_NONE)
				return -EFAULT;
			if (nexthdr == IPPROTO_FRAGMENT) {
				// First fragment still has L4; non-initial falls back.
				struct frag_hdr *fragh = data + offset;

				if ((void *)(fragh + 1) > data_end)
					return -1;
				__u16 frag_off = bpf_ntohs(fragh->frag_off);

				nexthdr = fragh->nexthdr;
				*l4proto = nexthdr;
				offset += sizeof(*fragh);
				if ((frag_off & 0xFFF8) != 0)
					return PARSE_FRAGMENT;
				continue;
			}
			if (!is_extension_header(nexthdr))
				break;

			ext_hdr = data + offset;
			if ((void *)(ext_hdr + 2) > data_end)
				return -1;

			__u8 cur_hdr = nexthdr;

			nexthdr = ext_hdr[0];
			offset += ipv6_exthdr_len(cur_hdr, ext_hdr[1]);
			*l4proto = nexthdr;
		}

		if (is_extension_header(nexthdr))
			return -EFAULT;

		// L4 parsing for IPv6
		switch (nexthdr) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph_ptr = data + offset;

			if ((void *)(tcph_ptr + 1) > data_end)
				return -1;
			tcph->source = tcph_ptr->source;
			tcph->dest = tcph_ptr->dest;
			tcph->seq = tcph_ptr->seq;
			tcph->ack_seq = tcph_ptr->ack_seq;
			// Data offset + flags, read through the raw accessors for
			// the same reason as the IP version/ihl byte above. The
			// reserved nibble is zero in a valid header and is not read
			// by any consumer of the copied struct.
			((__u8 *)tcph)[12] = tcph_doff(tcph_ptr) << 4;
			((__u8 *)tcph)[13] = tcph_flags(tcph_ptr);
			tcph->window = tcph_ptr->window;
			*listener_l4proto = tcp_listener_l4proto(tcph_ptr);
			return 0;
		}
		case IPPROTO_UDP: {
			struct udphdr *udph_ptr = data + offset;

			if ((void *)(udph_ptr + 1) > data_end)
				return -1;
			udph->source = udph_ptr->source;
			udph->dest = udph_ptr->dest;
			udph->len = udph_ptr->len;
			udph->check = udph_ptr->check;
			*listener_l4proto = IPPROTO_UDP;
			return 0;
		}
		case IPPROTO_ICMPV6: {
			struct icmp6hdr *icmp6h_ptr = data + offset;

			if ((void *)(icmp6h_ptr + 1) > data_end)
				return -1;
			icmp6h->icmp6_type = icmp6h_ptr->icmp6_type;
			icmp6h->icmp6_code = icmp6h_ptr->icmp6_code;
			return 0;
		}
		default:
			return PARSE_UNSUPPORTED_L4;
		}
	}

	return PARSE_UNSUPPORTED_ETH;
}

// Slow-path fallback using bpf_skb_load_bytes.
static __always_inline int
parse_transport_slow(struct __sk_buff *skb, __u32 link_h_len,
		     struct parse_transport_ctx *ctx)
{
	struct ethhdr *ethh = &ctx->ethh;
	struct iphdr *iph = &ctx->iph;
	struct ipv6hdr *ipv6h = &ctx->ipv6h;
	struct icmp6hdr *icmp6h = &ctx->icmp6h;
	struct tcphdr *tcph = &ctx->tcph;
	struct udphdr *udph = &ctx->udph;
	__u8 *ihl = &ctx->ihl;
	__u8 *l4proto = &ctx->l4proto;
	__u8 *listener_l4proto = &ctx->listener_l4proto;

	__u32 offset = 0;
	int ret;

	if (link_h_len == ETH_HLEN) {
		ret = bpf_skb_load_bytes(skb, offset, ethh,
					 sizeof(struct ethhdr));
		if (ret)
			return PARSE_UNSUPPORTED_ETH;
		offset += sizeof(struct ethhdr);
	} else {
		__builtin_memset(ethh, 0, sizeof(struct ethhdr));
		ethh->h_proto = skb->protocol;
	}

	*ihl = 0;
	*l4proto = 0;
	*listener_l4proto = 0;
	__builtin_memset(iph, 0, sizeof(struct iphdr));
	__builtin_memset(ipv6h, 0, sizeof(struct ipv6hdr));
	__builtin_memset(icmp6h, 0, sizeof(struct icmp6hdr));
	__builtin_memset(tcph, 0, sizeof(struct tcphdr));
	__builtin_memset(udph, 0, sizeof(struct udphdr));

	if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
		ret = bpf_skb_load_bytes(skb, offset, iph,
					 sizeof(struct iphdr));
		if (ret)
			return -EFAULT;
		if (iphdr_ihl(iph) < 5)
			return -EFAULT;
		*ihl = iphdr_ihl(iph);
		*l4proto = iph->protocol;

		// First fragment carries L4; non-initial falls back.
		__u16 frag_off = bpf_ntohs(iph->frag_off);

		if ((frag_off & 0x1FFF) != 0)
			return PARSE_FRAGMENT;

		offset += iphdr_ihl(iph) * 4;

		switch (iph->protocol) {
		case IPPROTO_TCP:
			ret = bpf_skb_load_bytes(skb, offset, tcph,
						 sizeof(struct tcphdr));
			if (ret)
				return -EFAULT;
			*listener_l4proto = tcp_listener_l4proto(tcph);
			break;
		case IPPROTO_UDP:
			ret = bpf_skb_load_bytes(skb, offset, udph,
						 sizeof(struct udphdr));
			if (ret)
				return -EFAULT;
			*listener_l4proto = IPPROTO_UDP;
			break;
		default:
			return PARSE_UNSUPPORTED_L4;
		}
		return 0;
	}

	if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
		ret = bpf_skb_load_bytes(skb, offset, ipv6h,
					 sizeof(struct ipv6hdr));
		if (ret)
			return -EFAULT;

		offset += sizeof(struct ipv6hdr);
		*ihl = sizeof(struct ipv6hdr) / 4;
		__u8 nexthdr = ipv6h->nexthdr;

		// Skip extension headers using bpf_skb_load_bytes
		for (int i = 0; i < IPV6_MAX_EXTENSIONS; i++) {
			if (nexthdr == IPPROTO_NONE)
				return -EFAULT;
			if (nexthdr == IPPROTO_FRAGMENT) {
				// First fragment still has L4; non-initial falls back.
				struct frag_hdr fragh = {};

				ret = bpf_skb_load_bytes(skb, offset, &fragh,
							 sizeof(fragh));
				if (ret)
					return -EFAULT;
				nexthdr = fragh.nexthdr;
				*l4proto = nexthdr;
				offset += sizeof(fragh);
				if ((bpf_ntohs(fragh.frag_off) & 0xFFF8) != 0)
					return PARSE_FRAGMENT;
				continue;
			}

			if (!is_extension_header(nexthdr))
				break;

			__u8 cur_hdr = nexthdr;

			ret = bpf_skb_load_bytes(skb, offset, &nexthdr, 1);
			if (ret)
				return -EFAULT;

			__u8 hdr_ext_len = 0;

			ret = bpf_skb_load_bytes(skb, offset + 1, &hdr_ext_len,
						 sizeof(hdr_ext_len));
			if (ret)
				return -EFAULT;

			__u32 ext_len = ipv6_exthdr_len(cur_hdr, hdr_ext_len);

			offset += ext_len;
		}

		if (is_extension_header(nexthdr))
			return -EFAULT;

		*l4proto = nexthdr;
		switch (nexthdr) {
		case IPPROTO_TCP:
			ret = bpf_skb_load_bytes(skb, offset, tcph,
						 sizeof(struct tcphdr));
			if (ret)
				return -EFAULT;
			*listener_l4proto = tcp_listener_l4proto(tcph);
			break;
		case IPPROTO_UDP:
			ret = bpf_skb_load_bytes(skb, offset, udph,
						 sizeof(struct udphdr));
			if (ret)
				return -EFAULT;
			*listener_l4proto = IPPROTO_UDP;
			break;
		case IPPROTO_ICMPV6:
			ret = bpf_skb_load_bytes(skb, offset, icmp6h,
						 sizeof(struct icmp6hdr));
			if (ret)
				return -EFAULT;
			break;
		default:
			return PARSE_UNSUPPORTED_L4;
		}
		return 0;
	}

	return PARSE_UNSUPPORTED_ETH;
}

// Try fast path first; fall back to slow path on -1.
static __always_inline int
parse_transport(struct __sk_buff *skb, __u32 link_h_len,
		struct parse_transport_ctx *ctx)
{
	int ret = parse_transport_fast(skb, link_h_len, ctx);

	if (ret == -1)
		return parse_transport_slow(skb, link_h_len, ctx);
	return ret;
}

struct parsed_packet {
	struct ethhdr ethh;
	struct tuples tuples;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 l4proto;
	__u8 listener_l4proto;
	__u8 handoff_required;
	__u16 datapath_generation;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct parsed_packet);
	__uint(max_entries, 1);
} pkt_scratch_map SEC(".maps");

static __always_inline void
populate_parsed_packet(struct __sk_buff *skb, struct parse_transport_ctx *ctx,
		       struct parsed_packet *out)
{
	__builtin_memset(out, 0, sizeof(*out));
	out->ethh = ctx->ethh;
	out->tcph = ctx->tcph;
	out->udph = ctx->udph;
	out->l4proto = ctx->l4proto;
	out->listener_l4proto = ctx->listener_l4proto;
	get_tuples(skb, &out->tuples, &ctx->iph, &ctx->ipv6h, &ctx->tcph,
		   &ctx->udph, ctx->l4proto);
}

static __always_inline int
parse_packet(struct __sk_buff *skb, __u32 link_h_len,
	     struct parsed_packet *out)
{
	__u32 scratch_key = 0;
	struct parse_transport_ctx *ctx =
		bpf_map_lookup_elem(&parse_ctx_scratch_map, &scratch_key);

	if (!ctx)
		return -EFAULT;

	int ret = parse_transport(skb, link_h_len, ctx);

	if (ret < 0)
		return ret;
	/* ICMPv6 is classified, but it is not proxied: report it through the
	 * same "L4 not routed" code so consumers count it uniformly. */
	if (ctx->l4proto == IPPROTO_ICMPV6)
		return PARSE_UNSUPPORTED_L4;

	// PARSE_FRAGMENT still populates the IP tuple for callers.
	populate_parsed_packet(skb, ctx, out);
	return ret;
}

struct route_ctx {
	__u32 flag[8];
	__u8 is_wan;
	__be32 mac[4];
	__u16 h_dport;
	__u16 h_sport;
	__s64 result;
	struct lpm_key lpm_key_saddr, lpm_key_daddr, lpm_key_mac;
	__u32 domain_word_idx;
	__u32 domain_word_bits;
	__u32 routing_epoch_slot;
	bool domain_word_cached;
	__u8 route_state;
};

struct route_loop_ctx {
	struct route_ctx *work;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct route_ctx);
	__uint(max_entries, 1);
} route_ctx_scratch_map SEC(".maps");

enum route_state_flags {
	ROUTE_STATE_BAD_RULE = 1U << 0,
	ROUTE_STATE_GOOD_SUBRULE = 1U << 1,
	ROUTE_STATE_MUST = 1U << 2,
	ROUTE_STATE_DNS_QUERY = 1U << 3,
};

struct wan_egress_route_scratch {
	__u32 flag[8];
	__be32 mac_be[4];
	__u8 is_wan;
	__u8 must_val;
	__u8 mac[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct wan_egress_route_scratch);
	__uint(max_entries, 1);
} wan_egress_route_scratch_map SEC(".maps");

// Per-CPU scratch to tunnel conntrack args past the BPF 5-argument limit.
#define CT_ARGS_HAS_ROUTING  BIT(0)
#define CT_ARGS_HAS_MAC      BIT(1)
#define CT_ARGS_HAS_PNAME    BIT(2)
/* Set by __mark_tcp_seen when a pure SYN reached a live ACTIVE flow and must
  * not rewrite its routing decision or reply binding . */
#define CT_ARGS_REBIND_LOCKED BIT(3)

struct conntrack_args {
	__u8 flags;        // CT_ARGS_HAS_* bitmask
	__u8 outbound;
	__u8 must;
	__u8 dscp;
	__u32 mark;
	__u32 pid;
	__u8 mac[6];
	__u8 routing_epoch_slot;
	__u8 padding;
	__u8 pname[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct conntrack_args);
	__uint(max_entries, 1);
} conntrack_args_map SEC(".maps");

static __always_inline void
conntrack_args_set(struct conntrack_args *a,
		   __u8 *outbound, __u32 *mark, __u8 *must, __u8 *mac,
		   __u8 dscp, const char *pname, __u32 pid,
		   __u8 routing_epoch_slot)
{
	__u8 flags = 0;

	a->outbound = 0;
	a->must = 0;
	a->dscp = dscp;
	a->mark = 0;
	a->pid = 0;
	a->routing_epoch_slot = ROUTING_EPOCH_SLOT_UNKNOWN;
	__builtin_memset(a->mac, 0, sizeof(a->mac));
	__builtin_memset(a->pname, 0, sizeof(a->pname));

	if (outbound) {
		flags |= CT_ARGS_HAS_ROUTING;
		a->outbound = *outbound;
		a->mark = *mark;
		a->must = *must;
		a->routing_epoch_slot =
			routing_epoch_slot_sanitize(routing_epoch_slot);
	}
	if (mac) {
		flags |= CT_ARGS_HAS_MAC;
		__builtin_memcpy(a->mac, mac, 6);
	}
	if (pname) {
		flags |= CT_ARGS_HAS_PNAME;
		__builtin_memcpy(a->pname, pname, TASK_COMM_LEN);
	}
	a->pid = pid;
	a->flags = flags;
}

static __always_inline int
route_match_lpm(struct route_ctx *ctx, const struct match_set *match_set,
		struct lpm_key *lpm_key)
{
	struct map_lpm_type *lpm;
	__u32 lpm_index;

	if (unlikely(ctx->routing_epoch_slot >= ROUTING_EPOCH_SLOT_NUM ||
		     match_set->index >= MAX_MATCH_SET_LEN)) {
		ctx->result = -EFAULT;
		return 1;
	}

	lpm_index = ctx->routing_epoch_slot * MAX_MATCH_SET_LEN +
		match_set->index;

	lpm = bpf_map_lookup_elem(&lpm_array_map, &lpm_index);
	if (unlikely(!lpm)) {
		ctx->result = -EFAULT;
		return 1;
	}

	if (bpf_map_lookup_elem(lpm, lpm_key)) {
		// match_set hits.
		ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
	}
	return 0;
}

static __always_inline struct lpm_key *
route_select_lpm_key(struct route_ctx *ctx, __u8 match_type)
{
	if (match_type == MatchType_Mac)
		return &ctx->lpm_key_mac;
	if (match_type == MatchType_IpSet)
		return &ctx->lpm_key_daddr;
	return &ctx->lpm_key_saddr;
}

static __always_inline int route_match_domain_set(struct route_ctx *ctx,
						  __u32 index)
{
	__u32 bitmap_word_idx;
	struct domain_routing *domain_routing;

	if (unlikely(index >= MAX_MATCH_SET_LEN)) {
		ctx->result = -EFAULT;
		return 1;
	}
	bitmap_word_idx = index >> 5;

	if (!ctx->domain_word_cached || ctx->domain_word_idx != bitmap_word_idx) {
		// Refresh one 32-rule bitmap word at a time.
		struct routing_epoch_ip daddr = {
			.slot = ctx->routing_epoch_slot,
		};

		__builtin_memcpy(daddr.addr, ctx->lpm_key_daddr.data,
				 sizeof(daddr.addr));
		domain_routing = bpf_map_lookup_elem(&domain_routing_map, &daddr);
		ctx->domain_word_idx = bitmap_word_idx;
		if (domain_routing)
			ctx->domain_word_bits =
				domain_routing->bitmap[bitmap_word_idx];
		else
			ctx->domain_word_bits = 0;
		ctx->domain_word_cached = true;
	}

	if ((ctx->domain_word_bits >> (index % 32)) & 1)
		ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
	return 0;
}

static __always_inline int
route_eval_match(struct route_ctx *ctx, const struct match_set *match_set,
		 __u32 index, __u8 l4proto_type, __u8 ipversion_type,
		 const __u32 *pname, __u8 is_wan, __u8 dscp)
{
	__u8 match_type = match_set->type;

	switch (match_type) {
	case MatchType_Mac:
	case MatchType_IpSet:
	case MatchType_SourceIpSet:
	{
		struct lpm_key *lpm_key = route_select_lpm_key(ctx, match_type);

#ifdef __DEBUG_ROUTING
		bpf_printk(
			"CHECK: lpm_key_map, match_set->type: %u, not: %d, outbound: %u",
			match_type, match_set->not, match_set->outbound);
		bpf_printk("\tip: %pI6", lpm_key->data);
#endif
		if (route_match_lpm(ctx, match_set, lpm_key))
			return 1;
		break;
	}
	case MatchType_Port:
	case MatchType_SourcePort:
	{
		__u16 check_port = match_type == MatchType_Port ? ctx->h_dport :
						      ctx->h_sport;
#ifdef __DEBUG_ROUTING
		bpf_printk(
			"CHECK: h_port_map, match_set->type: %u, not: %d, outbound: %u",
			match_type, match_set->not, match_set->outbound);
		bpf_printk("\tport: %u, range: [%u, %u]", check_port,
			   match_set->port_range.port_start,
			   match_set->port_range.port_end);
#endif
		if (check_port >= match_set->port_range.port_start &&
		    check_port <= match_set->port_range.port_end)
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	}
	case MatchType_L4Proto:
	case MatchType_IpVersion:
	{
		__u8 value = match_type == MatchType_L4Proto ? l4proto_type :
							      ipversion_type;
		__u8 mask = match_type == MatchType_L4Proto ?
				    match_set->l4proto_type :
				    match_set->ip_version;
#ifdef __DEBUG_ROUTING
		if (match_type == MatchType_L4Proto) {
			bpf_printk(
				"CHECK: l4proto, match_set->type: %u, not: %d, outbound: %u",
				match_type, match_set->not,
				match_set->outbound);
		} else {
			bpf_printk(
				"CHECK: ipversion, match_set->type: %u, not: %d, outbound: %u",
				match_type, match_set->not,
				match_set->outbound);
		}
#endif
		if (value & mask)
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	}
	case MatchType_DomainSet:
#ifdef __DEBUG_ROUTING
		bpf_printk(
			"CHECK: domain, match_set->type: %u, not: %d, outbound: %u",
			match_type, match_set->not, match_set->outbound);
#endif
		if (route_match_domain_set(ctx, index))
			return 1;
		break;
	case MatchType_ProcessName:
#ifdef __DEBUG_ROUTING
		bpf_printk(
			"CHECK: pname, match_set->type: %u, not: %d, outbound: %u",
			match_type, match_set->not, match_set->outbound);
#endif
		if (is_wan && equal16(match_set->pname, pname))
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	case MatchType_Dscp:
#ifdef __DEBUG_ROUTING
		bpf_printk(
			"CHECK: dscp, match_set->type: %u, not: %d, outbound: %u",
			match_type, match_set->not, match_set->outbound);
#endif
		if (dscp == match_set->dscp)
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	case MatchType_Fallback:
#ifdef __DEBUG_ROUTING
		bpf_printk("CHECK: hit fallback");
#endif
		ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	default:
#ifdef __DEBUG_ROUTING
		bpf_printk(
			"CHECK: <unknown>, match_set->type: %u, not: %d, outbound: %u",
			match_type, match_set->not, match_set->outbound);
#endif
		ctx->result = -EINVAL;
		return 1;
	}

	return 0;
}

static __always_inline int
route_finalize_match(struct route_ctx *ctx, const struct match_set *match_set)
{
	__u8 match_outbound = match_set->outbound;
	bool match_not = match_set->not;

#ifdef __DEBUG_ROUTING
	bpf_printk("good_subrule: %d, bad_rule: %d",
		   !!(ctx->route_state & ROUTE_STATE_GOOD_SUBRULE),
		   !!(ctx->route_state & ROUTE_STATE_BAD_RULE));
#endif
	if (match_outbound != OUTBOUND_LOGICAL_OR) {
		// This match_set reaches the end of subrule.
		// We are now at end of rule, or next match_set belongs to another
		// subrule.
		if (!!(ctx->route_state & ROUTE_STATE_GOOD_SUBRULE) == match_not)
			// This subrule does not hit.
			ctx->route_state |= ROUTE_STATE_BAD_RULE;

		// Reset good_subrule.
		ctx->route_state &= ~ROUTE_STATE_GOOD_SUBRULE;
	}
#ifdef __DEBUG_ROUTING
	bpf_printk("_bad_rule: %d", !!(ctx->route_state & ROUTE_STATE_BAD_RULE));
#endif
	if ((match_outbound & OUTBOUND_LOGICAL_MASK) != OUTBOUND_LOGICAL_MASK) {
		// Tail of a rule (line).
		// Decide whether to hit.
		if (!(ctx->route_state & ROUTE_STATE_BAD_RULE)) {
#ifdef __DEBUG_ROUTING
			bpf_printk(
				"MATCHED: match_set->type: %u, match_set->not: %d",
				match_set->type, match_not);
#endif
			// DNS requests should routed by control plane if outbound is not
			// must_direct.
			if (unlikely(match_outbound == OUTBOUND_MUST_RULES)) {
				ctx->route_state |= ROUTE_STATE_MUST;
			} else {
				bool must = !!(ctx->route_state & ROUTE_STATE_MUST) ||
					    match_set->must;

				if (!must &&
				    (ctx->route_state & ROUTE_STATE_DNS_QUERY)) {
					ctx->result =
						(__s64)OUTBOUND_CONTROL_PLANE_ROUTING |
						((__s64)match_set->mark << 8) |
						((__s64)must << 40);
#ifdef __DEBUG_ROUTING
					bpf_printk(
						"OUTBOUND_CONTROL_PLANE_ROUTING: %ld",
						ctx->result);
#endif
					return 1;
				}
				ctx->result = (__s64)match_outbound |
					      ((__s64)match_set->mark << 8) |
					      ((__s64)must << 40);
#ifdef __DEBUG_ROUTING
				bpf_printk("outbound %u: %ld",
					   match_outbound, ctx->result);
#endif
				return 1;
			}
		}
		ctx->route_state &= ~ROUTE_STATE_BAD_RULE;
	}
	return 0;
}

static __noinline int route_loop_cb(__u32 index, void *data)
{
	struct route_loop_ctx *loop = data;
	struct route_ctx *ctx = loop->work;
	struct match_set *match_set;
	__u8 l4proto_type = ctx->flag[0];
	__u8 ipversion_type = ctx->flag[1];
	const __u32 *pname = &ctx->flag[2];
	__u8 is_wan = ctx->is_wan;
	__u8 dscp = ctx->flag[6];
	volatile __u32 logical_index;

	// Rule is like: domain(suffix:baidu.com, suffix:google.com) && port(443) ->
	// proxy Subrule is like: domain(suffix:baidu.com, suffix:google.com) Match
	// set is like: suffix:baidu.com
	// Preserve the callback's u32 bound in the verifier.
	logical_index = index;

	if (unlikely(logical_index >= MAX_MATCH_SET_LEN)) {
		ctx->result = -EFAULT;
		return 1;
	}

	if (unlikely(ctx->routing_epoch_slot >= ROUTING_EPOCH_SLOT_NUM)) {
		ctx->result = -EFAULT;
		return 1;
	}

	__u32 k = ctx->routing_epoch_slot * MAX_MATCH_SET_LEN + logical_index;

	match_set = bpf_map_lookup_elem(&routing_map, &k);
	if (unlikely(!match_set)) {
		ctx->result = -EFAULT;
		return 1;
	}

	if (!(ctx->route_state &
	      (ROUTE_STATE_BAD_RULE | ROUTE_STATE_GOOD_SUBRULE))) {
		if (route_eval_match(ctx, match_set, logical_index, l4proto_type,
				     ipversion_type, pname, is_wan, dscp))
			return 1;
	} else {
#ifdef __DEBUG_ROUTING
		bpf_printk("key(match_set->type): %llu", match_set->type);
		bpf_printk("Skip to judge. bad_rule: %d, good_subrule: %d",
			   !!(ctx->route_state & ROUTE_STATE_GOOD_SUBRULE),
			   !!(ctx->route_state & ROUTE_STATE_BAD_RULE));
#endif
	}

	return route_finalize_match(ctx, match_set);
}

static __noinline __s64 route(const __u32 *flag, const void *l4hdr,
			      const __be32 *saddr, const __be32 *daddr,
			      const __be32 *mac)
{
#define _l4proto_type flag[0]
#define _ipversion_type flag[1]
#define _pname (&flag[2])
#define _is_wan flag[7]
#define _dscp flag[6]

	__u32 scratch_key = 0;
	struct route_ctx *ctx =
		bpf_map_lookup_elem(&route_ctx_scratch_map, &scratch_key);

	if (!ctx)
		return -EFAULT;

	__builtin_memset(ctx, 0, sizeof(*ctx));
	__builtin_memcpy(ctx->flag, flag, sizeof(ctx->flag));
	ctx->is_wan = _is_wan;
	__builtin_memcpy(ctx->mac, mac, sizeof(ctx->mac));
	ctx->result = -ENOEXEC;

	// Variables for further use.
	if (_l4proto_type == L4ProtoType_TCP) {
		ctx->h_dport = bpf_ntohs(((struct tcphdr *)l4hdr)->dest);
		ctx->h_sport =
			bpf_ntohs(((struct tcphdr *)l4hdr)->source);
	} else {
		ctx->h_dport = bpf_ntohs(((struct udphdr *)l4hdr)->dest);
		ctx->h_sport =
			bpf_ntohs(((struct udphdr *)l4hdr)->source);
	}

	// Rule is like: domain(suffix:baidu.com, suffix:google.com) && port(443) ->
	// proxy Subrule is like: domain(suffix:baidu.com, suffix:google.com) Match
	// set is like: suffix:baidu.com
	ctx->route_state =
		(ctx->h_dport == 53 &&
		 (_l4proto_type == L4ProtoType_UDP ||
		  _l4proto_type == L4ProtoType_TCP))
		? ROUTE_STATE_DNS_QUERY
		: 0;

	ctx->lpm_key_saddr.prefixlen = IPV6_BYTE_LENGTH * 8;
	ctx->lpm_key_daddr.prefixlen = IPV6_BYTE_LENGTH * 8;
	ctx->lpm_key_mac.prefixlen = IPV6_BYTE_LENGTH * 8;
	__builtin_memcpy(ctx->lpm_key_saddr.data, saddr,
			 IPV6_BYTE_LENGTH);
	__builtin_memcpy(ctx->lpm_key_daddr.data, daddr,
			 IPV6_BYTE_LENGTH);
	__builtin_memcpy(ctx->lpm_key_mac.data, mac, IPV6_BYTE_LENGTH);

	__u32 active_routing_epoch_slot = 0;
	__u32 *active_routing_epoch_slot_ptr =
		bpf_map_lookup_elem(&active_routing_epoch_map, &zero_key);
	__u32 active_rules_len = MAX_MATCH_SET_LEN;
	__u32 *active_rules_len_ptr =
		NULL;
	int ret;

	if (active_routing_epoch_slot_ptr) {
		active_routing_epoch_slot = *active_routing_epoch_slot_ptr;
		if (unlikely(active_routing_epoch_slot >= ROUTING_EPOCH_SLOT_NUM))
			return -EFAULT;
	}
	ctx->routing_epoch_slot = active_routing_epoch_slot;
	active_rules_len_ptr = bpf_map_lookup_elem(&routing_meta_map, &active_routing_epoch_slot);

	if (active_rules_len_ptr && *active_rules_len_ptr <= MAX_MATCH_SET_LEN)
		active_rules_len = *active_rules_len_ptr;

	struct route_loop_ctx loop_ctx = {
		.work = ctx,
	};
	ret = bpf_loop(active_rules_len, route_loop_cb, &loop_ctx, 0);
	if (unlikely(ret < 0))
		return ret;
	if (ctx->result >= 0) {
		// Preserve the policy slot alongside the existing packed result bits.
		return ctx->result |
		       ((__s64)routing_epoch_slot_encode(ctx->routing_epoch_slot)
			<< ROUTING_EPOCH_SLOT_RESULT_SHIFT);
	}
#ifdef __DEBUG_ROUTING
	bpf_printk(
		"No match_set hits. Did coder forget to sync common/consts/ebpf_sync_spec.json with enum MatchType?");
#endif
	return -EPERM;
#undef _l4proto_type
#undef _ipversion_type
#undef _pname
#undef _is_wan
#undef _dscp
}

static __always_inline int assign_listener(struct __sk_buff *skb, __u8 l4proto)
{
	struct bpf_sock *sk;
	const __u32 *key = &one_key;

	if (l4proto == IPPROTO_TCP)
		key = skb->protocol == bpf_htons(ETH_P_IPV6) ? &two_key : &zero_key;

	sk = bpf_map_lookup_elem(&listen_socket_map, key);

	if (!sk)
		return -1;

	int ret = bpf_sk_assign(skb, sk, 0);

	bpf_sk_release(sk);
	return ret;
}

/* get_dae0_ifindex returns the current dae0 ifindex, preferring the
 * runtime-updatable map over the frozen rodata constant. This allows
 * transparent recovery when dae0 is recreated with a new ifindex.
 */
static __always_inline __u32 get_dae0_ifindex(void)
{
	__u32 key = 0;
	__u32 *val = bpf_map_lookup_elem(&dae_ifindex_map, &key);

	if (val)
		return *val;
	return PARAM.dae0_ifindex;
}

static __always_inline int redirect_to_control_plane_ingress(void)
{
	__u32 ifindex = get_dae0_ifindex();
	// bpf_redirect_peer requires the CVE-2025-37959 fix (mainline >= 6.14.7
	// or official stable backports); the loader only sets
	// PARAM.use_redirect_peer on kernels known to contain it.
	if (PARAM.use_redirect_peer)
		return bpf_redirect_peer(ifindex, 0);
	return bpf_redirect(ifindex, 0);
}

static __always_inline int redirect_to_control_plane_egress(void)
{
	__u32 ifindex = get_dae0_ifindex();
	// bpf_redirect_peer is NOT supported in egress direction.
	// Only use it for ingress hooks.
	return bpf_redirect(ifindex, 0);
}

static __always_inline bool
wan_egress_needs_control_plane(__u8 outbound, __u32 mark)
{
	return !(outbound == OUTBOUND_DIRECT && mark == 0);
}

static __always_inline void
fill_routing_result(struct routing_result *dst,
		    __u32 mark, __u8 must, __u8 outbound,
		    const __u8 mac[6], __u8 dscp,
		    const char *pname, __u32 pid,
		    __u8 routing_epoch_slot, __u16 datapath_generation)
{
	__builtin_memset(dst, 0, sizeof(*dst));
	dst->mark = mark;
	dst->must = must;
	dst->outbound = outbound;
	dst->pid = pid;
	dst->dscp = dscp;
	dst->routing_epoch_slot =
		routing_epoch_slot_sanitize(routing_epoch_slot);
	dst->datapath_generation = datapath_generation;
	if (mac)
		__builtin_memcpy(dst->mac, mac, sizeof(dst->mac));
	if (pname)
		__builtin_memcpy(dst->pname, pname, TASK_COMM_LEN);
}

static __always_inline int
publish_routing_handoff(const struct tuples_key *tuples,
			const struct routing_result *result)
{
	struct routing_handoff_entry handoff = {};
	long ret;

	handoff.last_seen_ns = bpf_ktime_get_ns();
	handoff.result = *result;
	ret = bpf_map_update_elem(&routing_handoff_map, tuples, &handoff, BPF_ANY);
	if (ret)
		bpf_printk("routing_handoff update failed: %d", (int)ret);
	return (int)ret;
}

static __always_inline void
fill_redirect_tuple_from_forward_packet(const struct __sk_buff *skb,
					const struct tuples *tuples,
					struct redirect_tuple *redirect_tuple)
{
	__builtin_memset(redirect_tuple, 0, sizeof(*redirect_tuple));
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		redirect_tuple->sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple->sip.u6_addr32[3] = tuples->five.sip.u6_addr32[3];
		redirect_tuple->dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple->dip.u6_addr32[3] = tuples->five.dip.u6_addr32[3];
	} else {
		__builtin_memcpy(&redirect_tuple->sip, &tuples->five.sip,
				 IPV6_BYTE_LENGTH);
		__builtin_memcpy(&redirect_tuple->dip, &tuples->five.dip,
				 IPV6_BYTE_LENGTH);
	}
}

static __always_inline void
fill_redirect_entry_from_forward_packet(__u32 ifindex, __u32 link_h_len,
					const struct ethhdr *ethh, __u8 from_wan,
					struct redirect_entry *redirect_entry)
{
	__builtin_memset(redirect_entry, 0, sizeof(*redirect_entry));
	redirect_entry->ifindex = ifindex;
	redirect_entry->from_wan = from_wan;
	redirect_entry->last_seen_ns = bpf_ktime_get_ns();
	if (link_h_len == ETH_HLEN && ethh) {
		__builtin_memcpy(redirect_entry->smac, ethh->h_source, 6);
		__builtin_memcpy(redirect_entry->dmac, ethh->h_dest, 6);
	}
}

static __always_inline bool mac6_equal(const __u8 *a, const __u8 *b)
{
	for (int i = 0; i < 6; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

/* publish_redirect_track_for_packet stores the reply-path binding of a
 * redirected flow.
 *
  *: the entry is keyed by the forward tuple and carries the
 * interface/MAC to send replies to. Updating it unconditionally on every
 * redirected packet let a competing writer (e.g. a spoofer reusing the
 * victim's tuple) hand the victim's replies to itself for as long as it kept
 * sending. The entry is single-writer now:
 *   - same publisher (ifindex / from_wan / smac): refresh liveness in place;
 *   - different publisher on a fresh entry: keep the existing binding, count
 *     it and emit a rate-limited event;
 *   - different publisher on a stale entry: allow the rebind. A real LAN
 *     client that roams (Wi-Fi roam, VM migration) is silent for a while
 *     before it reappears on a new interface, so the window must stay short
 *     enough to recover the flow yet long enough to defeat a competing writer.
 * Every path that keeps an entry must refresh last_seen_ns: the userspace
 * janitor expires entries idle for redirectTrackTimeout, so skipping the
 * refresh would turn a live flow's reply path into a black hole.
 */
static __always_inline int
publish_redirect_track_for_packet(struct __sk_buff *skb, __u32 link_h_len,
				  const struct tuples *tuples,
				  const struct ethhdr *ethh, __u8 from_wan)
{
	struct redirect_tuple redirect_tuple = {};
	struct redirect_entry redirect_entry = {};
	struct redirect_entry *existing;
	long map_ret;

	fill_redirect_tuple_from_forward_packet(skb, tuples, &redirect_tuple);
	fill_redirect_entry_from_forward_packet(skb->ifindex, link_h_len, ethh,
						from_wan, &redirect_entry);

	existing = bpf_map_lookup_elem(&redirect_track, &redirect_tuple);
	if (existing) {
		bool same_publisher =
			existing->ifindex == redirect_entry.ifindex &&
			existing->from_wan == redirect_entry.from_wan &&
			mac6_equal(existing->smac, redirect_entry.smac);

		if (same_publisher) {
			existing->last_seen_ns = redirect_entry.last_seen_ns;
			return 0;
		}
		if (existing->last_seen_ns <= redirect_entry.last_seen_ns &&
		    redirect_entry.last_seen_ns - existing->last_seen_ns <
			    EVENT_RATE.redirect_rebind_stale_ns) {
			bump_stat(BPF_STATS_REDIRECT_REBIND_REJECTED);
			send_anomaly_event(EVENT_RATE.redirect_rebind_key,
					   DAE_EVENT_REDIRECT_REBIND_REJECTED,
					   tuples->five.l4proto, &tuples->five);
			return 0;
		}
	}

	map_ret = bpf_map_update_elem(&redirect_track, &redirect_tuple,
				      &redirect_entry, BPF_ANY);
	if (map_ret) {
		/* This used to be a bpf_printk, which the release build compiles
		 * to nothing (see the __DEBUG guard at the top of this file), so a
		 * saturated redirect_track silently lost the reply path. Count it
		 * (userspace sizes the map from these keys) and emit a
		 * rate-limited event instead. */
		if (map_ret == -E2BIG || map_ret == -ENOSPC)
			bump_stat(BPF_STATS_REDIRECT_OVERFLOW);
		else
			bump_stat(BPF_STATS_REDIRECT_UPDATE_FAILED);
		send_anomaly_event(EVENT_RATE.overflow_key,
				   DAE_EVENT_REDIRECT_UPDATE_FAILED,
				   tuples->five.l4proto, &tuples->five);
		return (int)map_ret;
	}
	return 0;
}

static __always_inline int
rewrite_packet_for_control_plane(struct __sk_buff *skb, __u32 link_h_len,
				 __u8 from_wan)
{
	bool use_redirect_peer = PARAM.use_redirect_peer && !from_wan;
	int ret;

	if (!use_redirect_peer) {
		if (!link_h_len) {
			__u16 l3proto = skb->protocol;
			__u8 zero_mac[6] = {0};

			ret = bpf_skb_change_head(skb, sizeof(struct ethhdr), 0);
			if (ret) {
				bpf_printk("prep_redirect: bpf_skb_change_head failed: %d", ret);
				return ret;
			}
			ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
						  &l3proto, sizeof(l3proto), 0);
			if (ret)
				return ret;
			ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
						  zero_mac, sizeof(zero_mac), 0);
			if (ret)
				return ret;
		}

		ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
					  (void *)&PARAM.dae0peer_mac, 6, 0);
		if (ret)
			return ret;
	}
	return 0;
}

static __noinline int prep_redirect_to_control_plane(
	struct __sk_buff *skb, __u32 link_h_len, struct tuples *tuples,
	struct ethhdr *ethh, __u8 from_wan)
{
	int ret = rewrite_packet_for_control_plane(skb, link_h_len, from_wan);

	if (ret)
		return ret;
	return publish_redirect_track_for_packet(skb, link_h_len, tuples, ethh,
						 from_wan);
}

static __always_inline void copy_reversed_tuples(struct tuples_key *key,
						 struct tuples_key *dst)
{
	__builtin_memset(dst, 0, sizeof(*dst));
	dst->dip = key->sip;
	dst->sip = key->dip;
	dst->sport = key->dport;
	dst->dport = key->sport;
	dst->l4proto = key->l4proto;
}

static __always_inline bool is_short_lived_udp_traffic(struct tuples_key *key)
{
	return key->l4proto == IPPROTO_UDP &&
	       (key->dport == bpf_htons(53) || key->sport == bpf_htons(53));
}

// mark_udp_seen: update/create UDP conn state with optional routing metadata.
// Expired entries are pruned on lookup. Map overflow increments bpf_stats_map.
// UDP_CONN_STATE_TIMEOUT_NS is overridable so test builds can shorten the
// backstop: with the 300-second value the expired-state path is unreachable on
// a host whose uptime is below it, because a seeded past timestamp wraps and
// udp_conn_state_expired() then treats the entry as live.
#ifndef UDP_CONN_STATE_TIMEOUT_NS
#define UDP_CONN_STATE_TIMEOUT_NS 300000000000ULL        // 300-second backstop, aligned with QuicNatTimeout; userspace endpoint teardown is the primary owner
#endif
#define UDP_CONN_STATE_UPDATE_INTERVAL_NS 1000000000ULL  // 1 second

enum udp_conn_state_status {
	UDP_CONN_STATE_STATUS_UNAVAILABLE = 0,
	UDP_CONN_STATE_STATUS_MISSING,
	UDP_CONN_STATE_STATUS_EXPIRED,
	UDP_CONN_STATE_STATUS_EXISTING,
	UDP_CONN_STATE_STATUS_CREATED,
	UDP_CONN_STATE_STATUS_OVERFLOW,
};

static __always_inline bool
udp_conn_state_expired(const struct conn_state *state, __u64 now)
{
	if (!state)
		return false;
	/* Guard against a timestamp in the future (clock slew, seeded state):
	 * without this, now - last_seen_ns underflows and live entries expire. */
	__u64 last_seen_ns = state->last_seen_ns;

	return now > last_seen_ns &&
	       now - last_seen_ns > UDP_CONN_STATE_TIMEOUT_NS;
}

static __always_inline bool
conntrack_args_are_empty(__u8 *outbound, __u32 *mark, __u8 *must, __u8 *mac,
			 __u8 dscp, const char *pname, __u32 pid,
			 __u8 routing_epoch_slot)
{
	return !outbound && !mark && !must && !mac && dscp == 0 && !pname &&
	       pid == 0 && routing_epoch_slot == ROUTING_EPOCH_SLOT_UNKNOWN;
}

static __noinline struct conn_state *
__mark_udp_seen(struct tuples_key *key, bool is_wan_ingress_direction,
		const struct conntrack_args *args, __u8 *status)
{
	struct conntrack_args empty_args = {};

	if (!args)
		args = &empty_args;
	if (status)
		*status = UDP_CONN_STATE_STATUS_MISSING;

	__u64 now = bpf_ktime_get_ns();
	struct conn_state *state =
		bpf_map_lookup_elem(&conn_state_map, key);

	if (udp_conn_state_expired(state, now)) {
		bpf_map_delete_elem(&conn_state_map, key);
		state = NULL;
		if (status)
			*status = UDP_CONN_STATE_STATUS_EXPIRED;
	}

	if (state) {
		if (status)
			*status = UDP_CONN_STATE_STATUS_EXISTING;
		// Fast path: lazy timestamp update (only if interval > 1 second)
		if (now - state->last_seen_ns > UDP_CONN_STATE_UPDATE_INTERVAL_NS)
			state->last_seen_ns = now;

		// Update routing if provided (e.g., routing decision changed)
		if (args->flags & CT_ARGS_HAS_ROUTING) {
			union routing_meta meta =
				build_routing_meta(args->outbound, args->mark,
						   args->must, args->dscp);

			if (args->flags & CT_ARGS_HAS_MAC)
				__builtin_memcpy(state->mac, args->mac, 6);
			if (args->flags & CT_ARGS_HAS_PNAME)
				__builtin_memcpy(state->pname, args->pname,
						 TASK_COMM_LEN);
			state->pid = args->pid;
			state->routing_epoch_slot = args->routing_epoch_slot;
			state->datapath_generation = PARAM.datapath_generation;
			publish_routing_meta(&state->meta, meta);
		}
		return state;
	}

	// Slow path: create new entry (either no entry or expired one was deleted)
	bool has_rt = !!(args->flags & CT_ARGS_HAS_ROUTING);
	struct conn_state new_state = {};

	new_state.is_wan_ingress_direction = is_wan_ingress_direction;
	new_state.last_seen_ns = now;
	new_state.meta.data.dscp = args->dscp;
	new_state.pid = args->pid;

	if (has_rt) {
		new_state.meta = build_routing_meta(args->outbound, args->mark,
						    args->must, args->dscp);
		if (args->flags & CT_ARGS_HAS_MAC)
			__builtin_memcpy(new_state.mac, args->mac, 6);
		if (args->flags & CT_ARGS_HAS_PNAME)
			__builtin_memcpy(new_state.pname, args->pname,
					 TASK_COMM_LEN);
		new_state.routing_epoch_slot = args->routing_epoch_slot;
		new_state.datapath_generation = PARAM.datapath_generation;
	}

	int ret = bpf_map_update_elem(&conn_state_map, key,
				      &new_state, BPF_ANY);

	if (unlikely(ret)) {
		if (status)
			*status = UDP_CONN_STATE_STATUS_OVERFLOW;
		/* Map full or other error: the per-packet counter always advances
		 * (userspace reads it to size the map), while the ringbuf event is
		 * rate-limited: a full map would otherwise emit one event per
		 * packet and starve the other event types. */
		__u32 stats_key = BPF_STATS_UDP_CONN_OVERFLOW;
		__u64 *overflow_count =
			bpf_map_lookup_elem(&bpf_stats_map, &stats_key);

		if (overflow_count)
			__sync_fetch_and_add(overflow_count, 1);
		if (!blocked_event_rate_limited(EVENT_RATE.overflow_key))
			send_dae_event(DAE_EVENT_UDP_CONN_OVERFLOW, args->pid,
				       (const char *)args->pname,
				       (args->flags & CT_ARGS_HAS_PNAME) != 0, 0,
				       key->l4proto, key->sip.u6_addr32,
				       key->dip.u6_addr32, key->sport,
				       key->dport);
		return NULL;
	}

	if (status)
		*status = UDP_CONN_STATE_STATUS_CREATED;
	return bpf_map_lookup_elem(&conn_state_map, key);
}

// mark_udp_seen_with_status is the shared wrapper for state updates that also
// exposes whether the key was already live to the caller.
static __always_inline struct conn_state *
mark_udp_seen_with_status(struct tuples_key *key, bool is_wan_ingress_direction,
			  __u8 *outbound, __u32 *mark, __u8 *must, __u8 *mac,
			  __u8 dscp, const char *pname, __u32 pid,
			  __u8 routing_epoch_slot, __u8 *status)
{
	if (conntrack_args_are_empty(outbound, mark, must, mac, dscp, pname, pid,
				     routing_epoch_slot))
		return __mark_udp_seen(key, is_wan_ingress_direction, NULL, status);

	__u32 zero = 0;
	struct conntrack_args *args =
		bpf_map_lookup_elem(&conntrack_args_map, &zero);

	if (unlikely(!args)) {
		if (status)
			*status = UDP_CONN_STATE_STATUS_UNAVAILABLE;
		return NULL;
	}
	conntrack_args_set(args, outbound, mark, must, mac, dscp, pname, pid,
			   routing_epoch_slot);
	return __mark_udp_seen(key, is_wan_ingress_direction, args, status);
}

static __always_inline struct conn_state *
mark_udp_seen(struct tuples_key *key, bool is_wan_ingress_direction,
	      __u8 *outbound, __u32 *mark, __u8 *must, __u8 *mac,
	      __u8 dscp, const char *pname, __u32 pid,
	      __u8 routing_epoch_slot)
{
	return mark_udp_seen_with_status(key, is_wan_ingress_direction, outbound,
					 mark, must, mac, dscp, pname, pid,
					 routing_epoch_slot, NULL);
}

// mark_tcp_seen: update/create TCP conn state with optional routing metadata.
// SYN starts new lifecycle; FIN/RST transitions to CLOSING.
#define TCP_CONN_STATE_CLOSING_TIMEOUT_NS 10000000000ULL       // 10 seconds
#define TCP_CONN_STATE_UPDATE_INTERVAL_NS 1000000000ULL  // 1 second

static __always_inline bool
tcp_conn_state_expired(const struct conn_state *state, __u64 now)
{
	/* ACTIVE entries may belong to process-owned sessions across reloads.
	 * Userspace owns their idle expiry because it can distinguish a live,
	 * pinned session from stale kernel state. */
	if (!state || state->state != TCP_STATE_CLOSING)
		return false;
	/* Same future-timestamp guard as the UDP expiry path: a last_seen_ns
	 * in the future would underflow and reap a live CLOSING entry early. */
	return now > state->last_seen_ns &&
	       now - state->last_seen_ns > TCP_CONN_STATE_CLOSING_TIMEOUT_NS;
}

/* routing_generation_matches reports whether a live flow's cached routing was
 * decided under the generation this packet belongs to.
 *
 * args->routing_epoch_slot is the epoch the packet was routed with: every SYN
 * path supplies the value route() packed into its result together with the
 * decision, and the paths that only refresh an entry pass UNKNOWN. A packet
 * that cannot name its epoch is not evidence of equality, so it never inherits
 * a live flow's cached routing.
 *
 * The routing epoch identifies the rule set: a slot's rules and routing metadata
 * are staged before the selector is published, and the selector only ever moves
 * to the slot prepared for the new generation, so "same slot" implies "same
 * rules". Equivalence between two generations is decided by the reload's staged
 * handoff; nothing here re-derives it, and a flow re-routed onto an equivalent
 * rule set simply lands on a byte-identical decision.
 *
 * A datapath generation marks the datapath that wrote an entry. It is frozen in
 * PARAM at load time, so an entry can only disagree with it when the pinned
 * conn_state_map outlived the datapath that created it (a pinned reload or an
 * in-place upgrade reusing the pin directory), and such an entry must not be
 * inherited either.
 */
static __always_inline bool
routing_generation_matches(const struct conn_state *state,
			   const struct conntrack_args *args)
{
	__u8 decision_slot = routing_epoch_slot_sanitize(args->routing_epoch_slot);
	__u8 entry_slot =
		routing_epoch_slot_sanitize(state->routing_epoch_slot);

	if (decision_slot == ROUTING_EPOCH_SLOT_UNKNOWN ||
	    entry_slot == ROUTING_EPOCH_SLOT_UNKNOWN)
		return false;
	if (decision_slot != entry_slot)
		return false;
	return state->datapath_generation == PARAM.datapath_generation;
}

// __mark_tcp_seen: noinline core. tcp_flags: bit 0 = SYN && !ACK (new
// connection), bit 1 = FIN || RST.
static __noinline struct conn_state *
__mark_tcp_seen(struct tuples_key *key, bool is_wan_ingress_direction,
		__u8 tcp_flags, struct conntrack_args *args)
{
	struct conntrack_args empty_args = {};

	if (!args)
		args = &empty_args;

	__u64 now = bpf_ktime_get_ns();
	struct conn_state *state =
		bpf_map_lookup_elem(&conn_state_map, key);
	bool new_conn_syn = tcp_flags & 1;
	bool is_fin_rst   = tcp_flags & 2;

	/*
	 * A pure SYN normally starts a fresh TCP lifecycle. If an older entry still
	 * exists under the same 4-tuple (for example because only the reverse-side
	 * FIN/RST was observed previously), drop it now so the new connection does
	 * not inherit stale routing metadata.
	 *
	 * Exception: an ACTIVE entry that carries a routing decision
	 * belongs to a live flow, and a same-tuple pure SYN is then an illegal
	 * mid-stream SYN that the kernel answers with a challenge ACK instead of
	 * opening a connection. Deleting the entry there let a single spoofed SYN
	 * re-route everything the flow sends afterwards — including its reply
	 * binding — for the rest of the flow's life, because an ACTIVE entry with
	 * routing metadata has no TTL to heal it. Refuse the rewrite instead:
	 * keep the entry, lock the rebind, count it and emit a rate-limited event.
	 *
	 * That protection is bound to the generation it was decided under. A
	 * connection that outlives a reload — the staged handoff let it drain
	 * instead of cutting it — still carries the old routing, while the
	 * rule the flow must follow is the current one: "after the rules changed,
	 * every new connection uses the new rules". The lock is therefore only
	 * granted while the decision's epoch (and the datapath that wrote it)
	 * still matches; otherwise the entry is dropped and re-created from the
	 * current generation. Equivalence is not re-derived here: reload decides
	 * it, and an equivalent re-route lands on a byte-identical decision.
	 */
	if (state && new_conn_syn) {
		if (state->state == TCP_STATE_ACTIVE &&
		    state->meta.data.has_routing &&
		    routing_generation_matches(state, args)) {
			/* Same generation: the flow keeps its routing. */
			args->flags |= CT_ARGS_REBIND_LOCKED;
			bump_stat(BPF_STATS_SYN_REBIND_REJECTED);
			send_anomaly_event(EVENT_RATE.syn_rebind_key,
					   DAE_EVENT_SYN_REBIND_REJECTED,
					   key->l4proto, key);
		} else {
			/* Either the entry carries no routing decision to
			 * inherit, or it carries one from another generation:
			 * drop it so the SYN below re-creates it from the
			 * current rules. Only the second case replaces a
			 * decision, so only it advances the re-route counter
			 * (the first is the plain stale-SYN path). */
			if (state->state == TCP_STATE_ACTIVE &&
			    state->meta.data.has_routing) {
				bump_stat(BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE);
				send_anomaly_event(
					EVENT_RATE.syn_rebind_key,
					DAE_EVENT_SYN_REBIND_REROUTED,
					key->l4proto, key);
			}
			bpf_map_delete_elem(&conn_state_map, key);
			state = NULL;
		}
	} else if (tcp_conn_state_expired(state, now)) {
		bpf_map_delete_elem(&conn_state_map, key);
		state = NULL;
	}

	if (state) {
		// Fast path: lazy timestamp update (only if interval > 1 second).
		// This must happen even for a locked rebind: an entry whose
		// last_seen_ns stopped advancing would be deleted by the userspace
		// janitor while the flow is still live, turning the reply path
		// into a black hole.
		if (now - state->last_seen_ns > TCP_CONN_STATE_UPDATE_INTERVAL_NS)
			state->last_seen_ns = now;

		// Check for connection close signals (FIN or RST)
		if (is_fin_rst)
			state->state = TCP_STATE_CLOSING;

		// Update routing if provided (rare: routing decision changed). A
		// locked rebind keeps both the routing decision and the side
		// fields that belong to the live flow.
		if (!(args->flags & CT_ARGS_REBIND_LOCKED) &&
		    (args->flags & CT_ARGS_HAS_ROUTING)) {
			union routing_meta meta =
				build_routing_meta(args->outbound, args->mark,
						   args->must, args->dscp);

			if (args->flags & CT_ARGS_HAS_MAC)
				__builtin_memcpy(state->mac, args->mac, 6);
			if (args->flags & CT_ARGS_HAS_PNAME)
				__builtin_memcpy(state->pname, args->pname,
						 TASK_COMM_LEN);
			state->pid = args->pid;
			state->routing_epoch_slot = args->routing_epoch_slot;
			state->datapath_generation = PARAM.datapath_generation;
			publish_routing_meta(&state->meta, meta);
		}

		return state;
	}

	// Only create new entry on SYN (new connection)
	if (new_conn_syn) {
		bool has_rt = !!(args->flags & CT_ARGS_HAS_ROUTING);
		struct conn_state new_state = {};

		new_state.is_wan_ingress_direction = is_wan_ingress_direction;
		new_state.state = TCP_STATE_ACTIVE;
		new_state.last_seen_ns = now;
		new_state.meta.data.dscp = args->dscp;
		new_state.pid = args->pid;

		if (has_rt) {
			new_state.meta = build_routing_meta(args->outbound,
							    args->mark,
							    args->must,
							    args->dscp);
			if (args->flags & CT_ARGS_HAS_MAC)
				__builtin_memcpy(new_state.mac, args->mac, 6);
			if (args->flags & CT_ARGS_HAS_PNAME)
				__builtin_memcpy(new_state.pname, args->pname,
						 TASK_COMM_LEN);
			new_state.routing_epoch_slot = args->routing_epoch_slot;
			new_state.datapath_generation = PARAM.datapath_generation;
		}

		int ret = bpf_map_update_elem(&conn_state_map, key,
					      &new_state, BPF_ANY);

		if (unlikely(ret)) {
			/* Per-packet counter + rate-limited event; see the UDP
			 * path above for why the event is throttled. */
			__u32 stats_key = BPF_STATS_TCP_CONN_OVERFLOW;
			__u64 *overflow_count =
				bpf_map_lookup_elem(&bpf_stats_map, &stats_key);

			if (overflow_count)
				__sync_fetch_and_add(overflow_count, 1);
			if (!blocked_event_rate_limited(EVENT_RATE.overflow_key))
				send_dae_event(DAE_EVENT_TCP_CONN_OVERFLOW,
					       args->pid,
					       (const char *)args->pname,
					       (args->flags &
						CT_ARGS_HAS_PNAME) != 0,
					       0, key->l4proto,
					       key->sip.u6_addr32,
					       key->dip.u6_addr32, key->sport,
					       key->dport);
			return NULL;
		}

		return bpf_map_lookup_elem(&conn_state_map, key);
	}

	// Non-SYN packets without existing state must never allocate new state.
	return NULL;
}

// mark_tcp_seen: thin inline wrapper that populates per-CPU scratch args once
// and then delegates to the single-copy __mark_tcp_seen body.
static __always_inline struct conn_state *
mark_tcp_seen(struct tuples_key *key, const struct tcphdr *tcph,
	      bool is_wan_ingress_direction,
	      __u8 *outbound, __u32 *mark, __u8 *must, __u8 *mac,
	      __u8 dscp, const char *pname, __u32 pid,
	      __u8 routing_epoch_slot)
{
	if (conntrack_args_are_empty(outbound, mark, must, mac, dscp, pname, pid,
				     routing_epoch_slot)) {
		__u8 tcp_flags = 0;
		__u8 flags = tcph_flags(tcph);

		if ((flags & TCPH_SYN) && !(flags & TCPH_ACK))
			tcp_flags |= 1;
		if (flags & (TCPH_FIN | TCPH_RST))
			tcp_flags |= 2;
		return __mark_tcp_seen(key, is_wan_ingress_direction, tcp_flags,
				       NULL);
	}

	__u32 zero = 0;
	struct conntrack_args *args =
		bpf_map_lookup_elem(&conntrack_args_map, &zero);

	if (unlikely(!args))
		return NULL;
	conntrack_args_set(args, outbound, mark, must, mac, dscp, pname, pid,
			   routing_epoch_slot);

	__u8 tcp_flags = 0;
	__u8 flags = tcph_flags(tcph);

	if ((flags & TCPH_SYN) && !(flags & TCPH_ACK))
		tcp_flags |= 1;
	if (flags & (TCPH_FIN | TCPH_RST))
		tcp_flags |= 2;
	return __mark_tcp_seen(key, is_wan_ingress_direction, tcp_flags, args);
}

static __always_inline bool is_new_tcp_connection(const struct tcphdr *tcph)
{
	__u8 flags = tcph_flags(tcph);

	return (flags & TCPH_SYN) && !(flags & TCPH_ACK);
}

// Reverse-direction conntrack refresh shared by standalone and combined LAN
// egress roles after a single packet parse.
static __always_inline int
tproxy_lan_egress_refresh(struct tuples *tuples, const struct tcphdr *tcph,
			  const struct udphdr *udph, __u8 l4proto)
{
	if (l4proto == IPPROTO_TCP) {
		struct tuples_key reversed_tuples_key;

		copy_reversed_tuples(&tuples->five, &reversed_tuples_key);
		// Reverse-side TCP packets should refresh the forward conn-state and
		// surface FIN/RST so the lifecycle does not remain ACTIVE until the
		// janitor backstop expires.
		mark_tcp_seen(&reversed_tuples_key, tcph, true,
			      NULL, NULL, NULL, NULL,
			      0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN);
	} else if (l4proto == IPPROTO_UDP) {
		if (udph->source == bpf_htons(53) || udph->dest == bpf_htons(53))
			return DAE_TC_CONTINUE;

		struct tuples_key reversed_tuples_key;

		copy_reversed_tuples(&tuples->five, &reversed_tuples_key);
		mark_udp_seen(&reversed_tuples_key, true,
			      NULL, NULL, NULL, NULL,
			      0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN);
	}

	return DAE_TC_CONTINUE;
}

// Reverse-direction conntrack refresh for LAN egress. When out is provided,
// retain the parsed packet for the combined LAN/WAN egress role.
static __noinline int
do_tproxy_lan_egress(struct __sk_buff *skb, __u32 link_h_len,
		     struct parsed_packet *out)
{
	__u32 scratch_key = 0;
	struct parse_transport_ctx *ctx =
		bpf_map_lookup_elem(&parse_ctx_scratch_map, &scratch_key);

	if (!ctx)
		return TC_ACT_SHOT;

	int ret = parse_transport(skb, link_h_len, ctx);

	if (ret) {
		// Negative: error - drop; Positive: unsupported protocol - pass through
		if (ret < 0) {
			bpf_printk("parse_transport error: %d, dropping", ret);
			return TC_ACT_SHOT;
		}
		report_parse_passthrough(ret);
		return TC_ACT_OK;
	}

	if (skb->ingress_ifindex == NOWHERE_IFINDEX &&  // Only drop NDP_REDIRECT packets from localhost
		ctx->l4proto == IPPROTO_ICMPV6 && ctx->icmp6h.icmp6_type == NDP_REDIRECT) {
		// REDIRECT (NDP)
		return TC_ACT_SHOT;
	}

	if (out) {
		populate_parsed_packet(skb, ctx, out);
		return tproxy_lan_egress_refresh(&out->tuples, &out->tcph, &out->udph,
						out->l4proto);
	}

	struct tuples tuples;

	get_tuples(skb, &tuples, &ctx->iph, &ctx->ipv6h,
		   &ctx->tcph, &ctx->udph, ctx->l4proto);
	return tproxy_lan_egress_refresh(&tuples, &ctx->tcph, &ctx->udph,
					ctx->l4proto);
}

SEC("tc/lan_egress_l2")
int tproxy_lan_egress_l2(struct __sk_buff *skb)
{
	return do_tproxy_lan_egress(skb, 14, NULL);
}

SEC("tc/lan_egress_l3")
int tproxy_lan_egress_l3(struct __sk_buff *skb)
{
	return do_tproxy_lan_egress(skb, 0, NULL);
}

static __noinline bool
wan_outbound_is_alive(struct __sk_buff *skb, __u8 outbound, __u8 l4proto,
		      __be16 dport);

static __noinline int
redirect_lan_packet_to_control_plane(struct __sk_buff *skb, __u32 link_h_len,
				     struct parsed_packet *pkt,
				     __u64 routing_meta_raw,
				     __u8 routing_epoch_slot)
{
	union routing_meta routing_meta = {
		.raw = routing_meta_raw,
	};

	if (prep_redirect_to_control_plane(skb, link_h_len, &pkt->tuples,
					   &pkt->ethh, 0)) {
		return TC_ACT_SHOT;
	}

	skb->cb[0] = TPROXY_MARK;
	skb->cb[1] = pkt->listener_l4proto;

	if (pkt->handoff_required) {
		struct routing_handoff_entry handoff = {};

		handoff.last_seen_ns = bpf_ktime_get_ns();
		handoff.result.mark = routing_meta.data.mark;
		handoff.result.must = routing_meta.data.must;
		handoff.result.outbound = routing_meta.data.outbound;
		handoff.result.dscp = routing_meta.data.dscp;
		handoff.result.routing_epoch_slot =
			routing_epoch_slot_sanitize(routing_epoch_slot);
		handoff.result.datapath_generation = pkt->datapath_generation;
		__builtin_memcpy(handoff.result.mac, pkt->ethh.h_source, 6);
		bpf_map_update_elem(&routing_handoff_map, &pkt->tuples.five,
				    &handoff, BPF_ANY);
	}
	return redirect_to_control_plane_ingress();
}

/* LAN-ingress role body. Takes the packet already parsed by the middle layer
 * so that a dual-role attachment (wan_lan_ingress) parses exactly once. Kept
 * inline so the role's locals live in whichever middle-layer frame drives it
 * (the combined 512-byte stack budget of the call chains is tight). */
static __always_inline int
tproxy_lan_ingress_role(struct __sk_buff *skb, __u32 link_h_len,
			struct parsed_packet *pkt)
{
	/*
   * ip rule add fwmark 0x8000000/0x8000000 table 2023
   * ip route add local default dev lo table 2023
   * ip -6 rule add fwmark 0x8000000/0x8000000 table 2023
   * ip -6 route add local default dev lo table 2023

   * ip rule del fwmark 0x8000000/0x8000000 table 2023
   * ip route del local default dev lo table 2023
   * ip -6 rule del fwmark 0x8000000/0x8000000 table 2023
   * ip -6 route del local default dev lo table 2023
   */
	if (pkt->l4proto == IPPROTO_TCP &&
	    !is_new_tcp_connection(&pkt->tcph)) {
		__u8 outbound;
		__u32 mark;
		struct conn_state *tcp_state;

		// Track TCP connection state; reuse returned pointer.
		tcp_state = mark_tcp_seen(&pkt->tuples.five, &pkt->tcph, false,
					  NULL, NULL, NULL, NULL,
					  0, NULL, 0,
					  ROUTING_EPOCH_SLOT_UNKNOWN);
		/* No cached state for an established packet: keep the historical
		 * passthrough behavior instead of recomputing routing, and count
		 * it without warning per event. This is what every
		 * pre-existing TCP flow does after a restart, and it silently
		 * bypasses routing today: a steady state must not log one line
		 * per second, so the counter is the per-packet record and
		 * userspace reports its interval delta
		 * (reportDatapathPassthroughSummary in control/control_plane.go).
		 */
		if (!tcp_state) {
			bump_stat(BPF_STATS_STATELESS_TCP_PASSTHROUGH);
			return TC_ACT_OK;
		}

		/* Compatibility restore for 030902f behavior and align with WAN
		 * non-SYN session handling: reuse cached routing result for
		 * established TCP packets.
		 */
		if (!tcp_state->meta.data.has_routing) {
			/* No cache: keep historical direct-pass semantics (e.g.
			 * single-arm / reply-path traffic).
			 */
			return TC_ACT_OK;
		}

		// Load routing from the conn_state we already looked up
		outbound = tcp_state->meta.data.outbound;
		mark = tcp_state->meta.data.mark;

		if (outbound == OUTBOUND_DIRECT) {
			skb->mark = mark;
			return TC_ACT_OK;
		}
		if (unlikely(outbound == OUTBOUND_BLOCK))
			return TC_ACT_SHOT;
		pkt->datapath_generation = tcp_state->datapath_generation;
		return redirect_lan_packet_to_control_plane(
			skb, link_h_len, pkt, tcp_state->meta.raw,
			tcp_state->routing_epoch_slot);
	}

	// Routing for new connection.
	__u32 route_flag[8] = {};
	struct conn_state *tcp_state = NULL;
	struct conn_state *udp_state = NULL;
	__u8 udp_state_status = UDP_CONN_STATE_STATUS_UNAVAILABLE;

	if (pkt->l4proto == IPPROTO_TCP) {
		// Track TCP connection state for new connections from LAN.
		// This ensures routing cache entries can be cleaned up via
		// cascade deletion when the connection expires.
		tcp_state = mark_tcp_seen(&pkt->tuples.five, &pkt->tcph, false,
					  NULL, NULL, NULL, NULL,
					  pkt->tuples.dscp, NULL, 0,
					  ROUTING_EPOCH_SLOT_UNKNOWN);
		route_flag[0] = L4ProtoType_TCP;
	} else {
		if (!is_short_lived_udp_traffic(&pkt->tuples.five)) {
			// Fast path: Check conn state for established UDP flows
			udp_state = mark_udp_seen_with_status(
				&pkt->tuples.five, false, NULL, NULL, NULL, NULL,
				pkt->tuples.dscp, NULL, 0,
				ROUTING_EPOCH_SLOT_UNKNOWN, &udp_state_status);
			if (udp_state && udp_state->is_wan_ingress_direction) {
				// Replay (outbound) of an inbound flow => direct.
				return TC_ACT_OK;
			}

			// Fast path: Use cached routing if available
			if (udp_state && udp_state->meta.data.has_routing) {
				// Load routing from conn state - skip expensive route call!
				__u8 outbound = udp_state->meta.data.outbound;
				__u32 mark = udp_state->meta.data.mark;

				if (outbound == OUTBOUND_DIRECT) {
					skb->mark = mark;
					goto direct;
				} else if (unlikely(outbound == OUTBOUND_BLOCK)) {
					goto block;
				}

				/* last_seen_ns already refreshed by mark_udp_seen. */
				pkt->datapath_generation = udp_state->datapath_generation;
				return redirect_lan_packet_to_control_plane(
					skb, link_h_len, pkt, udp_state->meta.raw,
					udp_state->routing_epoch_slot);
			}
		}
		route_flag[0] = L4ProtoType_UDP;
	}
	route_flag[1] = (skb->protocol == bpf_htons(ETH_P_IP)) ? IpVersionType_4 :
							      IpVersionType_6;
	route_flag[6] = pkt->tuples.dscp;
	__be32 mac_be[4] = {
		0,
		0,
		bpf_htonl(((__u32)pkt->ethh.h_source[0] << 8) |
			  (__u32)pkt->ethh.h_source[1]),
		bpf_htonl(((__u32)pkt->ethh.h_source[2] << 24) |
			  ((__u32)pkt->ethh.h_source[3] << 16) |
			  ((__u32)pkt->ethh.h_source[4] << 8) |
			  (__u32)pkt->ethh.h_source[5]),
	};

	// Socket lookup before routing to detect a service on this host that the
	// packet is addressed to (NAT loopback). Only a socket bound to the
	// packet's exact destination address proves that: a wildcard-bound socket
	// answers for any destination, so it must not capture traffic addressed
	// elsewhere, and it must never capture DNS. TCP is not looked up here
	// because every non-SYN TCP packet already returned above.
	if (pkt->l4proto == IPPROTO_UDP &&
	    pkt->tuples.five.dport != bpf_htons(53)) {
		struct bpf_sock_tuple tuple = { 0 };
		__u32 tuple_size;
		struct bpf_sock *sk;

		// Use ethh->h_proto instead of skb->protocol for consistency
		// with parse_transport and to handle L3-only packets correctly
		if (pkt->ethh.h_proto == bpf_htons(ETH_P_IP)) {
			tuple.ipv4.daddr = pkt->tuples.five.dip.u6_addr32[3];
			tuple.ipv4.saddr = pkt->tuples.five.sip.u6_addr32[3];
			tuple.ipv4.dport = pkt->tuples.five.dport;
			tuple.ipv4.sport = pkt->tuples.five.sport;
			tuple_size = sizeof(tuple.ipv4);
		} else {
			__builtin_memcpy(tuple.ipv6.daddr, &pkt->tuples.five.dip,
					 IPV6_BYTE_LENGTH);
			__builtin_memcpy(tuple.ipv6.saddr, &pkt->tuples.five.sip,
					 IPV6_BYTE_LENGTH);
			tuple.ipv6.dport = pkt->tuples.five.dport;
			tuple.ipv6.sport = pkt->tuples.five.sport;
			tuple_size = sizeof(tuple.ipv6);
		}

		/* Look up in the netns of the hook (the LAN-side host netns):
		 * dae_netns_id would search dae's own netns, which can only ever
		 * match dae sockets and makes the local-service branch below
		 * unreachable. -1 selects "the netns of ctx".
		 */
		sk = bpf_sk_lookup_udp(skb, &tuple, tuple_size,
				       (__u64)(s32)-1, 0);
		if (sk) {
			if (!bpf_sock_is_dae_socket(sk) &&
			    sock_bound_to_daddr(sk, &pkt->tuples,
						pkt->ethh.h_proto)) {
				bpf_sk_release(sk);
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
				bpf_printk("udp(lan): local socket bound to the destination, pass through");
#endif
				return TC_ACT_OK;
			}
			bpf_sk_release(sk);
		}
	}

	__s64 s64_ret;

	s64_ret = route(route_flag,
			pkt->l4proto == IPPROTO_TCP ? (const void *)&pkt->tcph :
						      (const void *)&pkt->udph,
			pkt->tuples.five.sip.u6_addr32,
			pkt->tuples.five.dip.u6_addr32,
			mac_be);
	if (s64_ret < 0) {
		bpf_printk("shot routing: %d", s64_ret);
		return TC_ACT_SHOT;
	}

	__u8 outbound = s64_ret & 0xff;
	__u32 mark = s64_ret >> 8;
	__u8 must = (s64_ret >> 40) & 1;
	__u8 routing_epoch_slot =
		routing_epoch_slot_from_route_result(s64_ret);

	// Cache routing in conn state (skip DNS to avoid map churn).
	if (pkt->l4proto == IPPROTO_UDP &&
	    is_short_lived_udp_traffic(&pkt->tuples.five)) {
		// Skip cache for short-lived DNS to avoid map churn.
	} else if (pkt->l4proto == IPPROTO_TCP && tcp_state) {
		// Directly update the TCP conn state we already looked up
		__builtin_memcpy(tcp_state->mac, pkt->ethh.h_source, 6);
		tcp_state->routing_epoch_slot = routing_epoch_slot;
		tcp_state->datapath_generation = PARAM.datapath_generation;
		union routing_meta _m = build_routing_meta(outbound, mark, must,
						    pkt->tuples.dscp);
		publish_routing_meta(&tcp_state->meta, _m);
	} else if (pkt->l4proto == IPPROTO_UDP && udp_state) {
		// Directly update the UDP conn state we already looked up
		__builtin_memcpy(udp_state->mac, pkt->ethh.h_source, 6);
		udp_state->routing_epoch_slot = routing_epoch_slot;
		udp_state->datapath_generation = PARAM.datapath_generation;
		union routing_meta _m = build_routing_meta(outbound, mark, must,
							    pkt->tuples.dscp);
		publish_routing_meta(&udp_state->meta, _m);
	}

	// Fail-closed: TCP without conn state must drop to prevent traffic leakage.
	if (pkt->l4proto == IPPROTO_TCP && !tcp_state) {
		if (outbound == OUTBOUND_DIRECT && mark == 0) {
			skb->mark = mark;
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
			bpf_printk("tcp(lan): GO OUTBOUND_DIRECT (MAP FULL)");
#endif
			goto direct;
		}
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		if (outbound == OUTBOUND_DIRECT)
			bpf_printk("tcp(lan): SHOT - MAP FULL, DIRECT WITH NON-ZERO MARK DROPPED");
		else
			bpf_printk("tcp(lan): SHOT - MAP FULL, PROXY CONNECTION DROPPED");
#endif
		goto block;
	}

#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
	if (pkt->l4proto == IPPROTO_TCP) {
		bpf_printk("tcp(lan): outbound: %u, target: %pI6:%u", outbound,
			   pkt->tuples.five.dip.u6_addr32,
			   bpf_ntohs(pkt->tuples.five.dport));
	} else {
		bpf_printk("udp(lan): outbound: %u, target: %pI6:%u", outbound,
			   pkt->tuples.five.dip.u6_addr32,
			   bpf_ntohs(pkt->tuples.five.dport));
	}
#endif

	if (outbound == OUTBOUND_DIRECT) {
		skb->mark = mark;
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("GO OUTBOUND DIRECT");
#endif
		goto direct;
	} else if (unlikely(outbound == OUTBOUND_BLOCK)) {
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("SHOT OUTBOUND_BLOCK");
#endif
		send_blocked_event(outbound, pkt->l4proto,
				   pkt->tuples.five.sip.u6_addr32,
				   pkt->tuples.five.dip.u6_addr32,
				   pkt->tuples.five.sport, pkt->tuples.five.dport);
		goto block;
	}

	if (!wan_outbound_is_alive(skb, outbound, pkt->l4proto,
				   pkt->tuples.five.dport)) {
		send_blocked_alive_event(outbound, pkt->l4proto,
					 pkt->tuples.five.sip.u6_addr32,
					 pkt->tuples.five.dip.u6_addr32,
					 pkt->tuples.five.sport,
					 pkt->tuples.five.dport);
		goto block;
	}
	pkt->datapath_generation = PARAM.datapath_generation;
	pkt->handoff_required =
		(pkt->l4proto == IPPROTO_TCP && tcp_state) ||
		(pkt->l4proto == IPPROTO_UDP &&
		 udp_state_status != UDP_CONN_STATE_STATUS_EXISTING);
	return redirect_lan_packet_to_control_plane(
		skb, link_h_len, pkt,
		build_routing_meta(outbound, mark, must, pkt->tuples.dscp).raw,
		routing_epoch_slot);

direct:
	return TC_ACT_OK;

block:
	return TC_ACT_SHOT;
}

/* Middle layer: parse once, then run the LAN-ingress role. One call frame, as
 * before the role was split out, so the callers' stack chains do not grow. */
static __noinline int do_tproxy_lan_ingress(struct __sk_buff *skb, __u32 link_h_len)
{
	// Per-CPU scratch to stay under 512-byte stack limit.
	__u32 scratch_key = 0;
	struct parsed_packet *pkt =
		bpf_map_lookup_elem(&pkt_scratch_map, &scratch_key);

	if (!pkt)
		return TC_ACT_SHOT;

	/* Ensure scratch bytes are initialized even if verifier can't precisely
	 * track writes done through callee pointer arguments. */
	__builtin_memset(pkt, 0, sizeof(*pkt));
	int ret = parse_packet(skb, link_h_len, pkt);

	if (ret) {
		if (ret < 0) {
			bpf_printk("parse_transport error: %d, dropping", ret);
			return TC_ACT_SHOT;
		}
		report_parse_passthrough(ret);
		return TC_ACT_OK;
	}

	return tproxy_lan_ingress_role(skb, link_h_len, pkt);
}

SEC("tc/lan_ingress_l2")
int tproxy_lan_ingress_l2(struct __sk_buff *skb)
{
	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/lan_ingress_l3")
int tproxy_lan_ingress_l3(struct __sk_buff *skb)
{
	return do_tproxy_lan_ingress(skb, 0);
}

static __always_inline void
refresh_cookie_pid_last_seen(struct pid_pname *pid_pname)
{
	__u64 now = bpf_ktime_get_ns();

	if (now - pid_pname->last_seen_ns > COOKIE_PID_UPDATE_INTERVAL_NS)
		pid_pname->last_seen_ns = now;
}

// Cookie will change after the first packet, so we just use it for
// handshake.
static __always_inline bool pid_is_control_plane(struct __sk_buff *skb,
						 struct pid_pname **p)
{
	struct pid_pname *pid_pname;
	__u64 cookie = bpf_get_socket_cookie(skb);

	pid_pname = bpf_map_lookup_elem(&cookie_pid_map, &cookie);
	if (pid_pname) {
		refresh_cookie_pid_last_seen(pid_pname);
		if (p) {
			// Assign.
			*p = pid_pname;
		}
		// Get tproxy pid and compare if they are equal.
		__u32 pid_tproxy;

		pid_tproxy = PARAM.control_plane_pid;
		if (!pid_tproxy) {
			bpf_printk("control_plane_pid is not set.");
			return false;
		}
		return pid_pname->pid == pid_tproxy;
	}
	if (p)
		*p = NULL;
	/* Fallback for sockets that missed cookie_pid_map (e.g. non-handshake
	 * packets): compare the exact fwmark configured for dae's own sockets.
	 * Comparing the whole mark is what keeps a foreign mark that merely
	 * carries the reserved bit (0x105, 0x1100, ...) from being classified
	 * as dae's own traffic and skipping the entire routing pass. The
	 * reserved-bit test survives only as the last resort for a datapath
	 * whose so_mark was never injected, and it is counted so that such a
	 * deployment is visible instead of silently over-matching. */
	if (PARAM.dae_socket_mark)
		return skb->mark == PARAM.dae_socket_mark;
	bump_stat(BPF_STATS_SOCKMARK_FALLBACK);
	return (skb->mark & 0x100) == 0x100;
}

/* WAN-ingress role body. Takes the packet already parsed by the middle layer
 * so a dual-role attachment (wan_lan_ingress) parses exactly once. */
static __always_inline int
tproxy_wan_ingress_role(struct __sk_buff *skb, __u32 link_h_len,
			struct parsed_packet *pkt)
{
	// Reverse-direction conntrack refresh.
	if (pkt->l4proto == IPPROTO_TCP) {
		struct tuples_key reversed_tuples_key;

		copy_reversed_tuples(&pkt->tuples.five, &reversed_tuples_key);
		mark_tcp_seen(&reversed_tuples_key, &pkt->tcph, true,
			      NULL, NULL, NULL, NULL,
			      0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN);
	} else if (pkt->l4proto == IPPROTO_UDP) {
		struct tuples_key reversed_tuples_key;
		__u8 state_status = UDP_CONN_STATE_STATUS_UNAVAILABLE;

		if (pkt->udph.source == bpf_htons(53) ||
		    pkt->udph.dest == bpf_htons(53))
			return DAE_TC_CONTINUE;

		copy_reversed_tuples(&pkt->tuples.five, &reversed_tuples_key);
		/* Observability only: an unsolicited WAN-ingress UDP flow would
		 * otherwise create conn_state from the outside (262144 entries
		 * over a 300s TTL is only ~874 new flows per second). Rejecting
		 * it would also drop the is_wan_ingress_direction marker that the
		 * wan_egress pass-through depends on (host-terminated UDP
		 * services), so this is counted, not enforced. See fix-plan.md
		 * decision A20. */
		mark_udp_seen_with_status(&reversed_tuples_key, true,
					  NULL, NULL, NULL, NULL,
					  0, NULL, 0,
					  ROUTING_EPOCH_SLOT_UNKNOWN, &state_status);
		if (state_status != UDP_CONN_STATE_STATUS_EXISTING &&
		    state_status != UDP_CONN_STATE_STATUS_UNAVAILABLE)
			bump_stat(BPF_STATS_UNSOLICITED_UDP_SEEN);
	}

	return DAE_TC_CONTINUE;
}

/* Middle layer for the WAN-ingress role; see do_tproxy_lan_ingress. */
static __noinline int do_tproxy_wan_ingress(struct __sk_buff *skb, __u32 link_h_len)
{
	__u32 scratch_key = 0;
	struct parsed_packet *pkt =
		bpf_map_lookup_elem(&pkt_scratch_map, &scratch_key);

	if (!pkt)
		return TC_ACT_SHOT;

	__builtin_memset(pkt, 0, sizeof(*pkt));
	int ret = parse_packet(skb, link_h_len, pkt);

	if (ret) {
		// Negative: error - drop; Positive: unsupported protocol - pass through
		if (ret < 0) {
			bpf_printk("parse_transport error: %d, dropping", ret);
			return TC_ACT_SHOT;
		}
		report_parse_passthrough(ret);
		return TC_ACT_OK;
	}

	return tproxy_wan_ingress_role(skb, link_h_len, pkt);
}

SEC("tc/wan_ingress_l2")
int tproxy_wan_ingress_l2(struct __sk_buff *skb)
{
	return do_tproxy_wan_ingress(skb, 14);
}

SEC("tc/wan_ingress_l3")
int tproxy_wan_ingress_l3(struct __sk_buff *skb)
{
	return do_tproxy_wan_ingress(skb, 0);
}

/* Dual-role hook: parse the packet once and run both roles on the same parsed
 * result. Parsing twice was both wasteful and a correctness hazard: the two
 * roles could observe different parser outcomes (e.g. the fast path falling
 * back to the slow path between calls) and disagree on forwarding. */
static __noinline int
do_tproxy_wan_lan_ingress(struct __sk_buff *skb, __u32 link_h_len)
{
	__u32 scratch_key = 0;
	struct parsed_packet *pkt =
		bpf_map_lookup_elem(&pkt_scratch_map, &scratch_key);

	if (!pkt)
		return TC_ACT_SHOT;

	__builtin_memset(pkt, 0, sizeof(*pkt));
	int ret = parse_packet(skb, link_h_len, pkt);

	if (ret) {
		if (ret < 0) {
			bpf_printk("wan_lan_ingress parse error: %d, dropping",
				   ret);
			return TC_ACT_SHOT;
		}
		report_parse_passthrough(ret);
		/* The wan_ingress role used to consume the packet first and
		 * return TC_ACT_OK for an unclassifiable frame, which made the
		 * dual-role hook stop before the lan_ingress role. Preserve
		 * that forwarding decision. */
		return TC_ACT_OK;
	}

	ret = tproxy_wan_ingress_role(skb, link_h_len, pkt);
	if (ret != DAE_TC_CONTINUE)
		return ret;
	return tproxy_lan_ingress_role(skb, link_h_len, pkt);
}

SEC("tc/wan_lan_ingress_l2")
int tproxy_wan_lan_ingress_l2(struct __sk_buff *skb)
{
	return do_tproxy_wan_lan_ingress(skb, 14);
}

SEC("tc/wan_lan_ingress_l3")
int tproxy_wan_lan_ingress_l3(struct __sk_buff *skb)
{
	return do_tproxy_wan_lan_ingress(skb, 0);
}

// Routing and redirect the packet back.
// We cannot modify the dest address here. So we cooperate with wan_ingress.
static __noinline bool
wan_outbound_is_alive(struct __sk_buff *skb, __u8 outbound, __u8 l4proto,
		      __be16 dport)
{
	/* Reserved outbounds (must_rules, control-plane routing, logical
	 * markers) have no connectivity entries: the map below is sized for
	 * user-defined ids only, so a reserved id would read a zeroed entry
	 * and silently drop the flow. This includes the control-plane punt
	 * outbound used by implicit sniff-punt rules; DNS bypasses below for
	 * the same reason. */
	if (outbound >= OUTBOUND_MUST_RULES)
		return true;

	/* DNS must always reach control plane; userspace handles fallback. */
	if (dport == bpf_htons(53))
		return true;

	// ARRAY map key: outbound_id * 6 + domain * 2 + ipversion
	// domain: 0=TCP, 1=DNS UDP, 2=data UDP; ipversion: 0=IPv4, 1=IPv6
	__u32 domain_idx = 0;
	__u32 ip_idx = skb->protocol == bpf_htons(ETH_P_IP) ? 0 : 1;
	__u32 key;
	__u32 *alive;

	if (l4proto == IPPROTO_UDP) {
		if (dport == bpf_htons(53))
			domain_idx = 1;
		else
			domain_idx = 2;
	}
	key = ((__u32)outbound * 6) + (domain_idx * 2) + ip_idx;
	alive = bpf_map_lookup_elem(&outbound_connectivity_map, &key);
	if (alive && *alive == 0)
		return false;
	return true;
}

static __noinline int
do_tproxy_wan_egress_tcp(struct __sk_buff *skb, __u32 link_h_len,
			 struct tuples *tuples, struct ethhdr *ethh,
			 struct tcphdr *tcph)
{
	bool tcp_state_syn = is_new_tcp_connection(tcph);
	__u8 outbound;
	bool must;
	__u32 mark;
	struct pid_pname *pid_pname = NULL;
	const char *handoff_pname = NULL;
	__u32 handoff_pid = 0;
	__u8 handoff_mac[6] = {};
	__u8 routing_epoch_slot = ROUTING_EPOCH_SLOT_UNKNOWN;
	__u16 datapath_generation = PARAM.datapath_generation;
	__u32 scratch_key = 0;
	struct wan_egress_route_scratch *scratch =
		bpf_map_lookup_elem(&wan_egress_route_scratch_map, &scratch_key);

	if (!scratch)
		return TC_ACT_SHOT;

	if (unlikely(tcp_state_syn)) {
		__builtin_memset(scratch, 0, sizeof(*scratch));
		scratch->flag[0] = L4ProtoType_TCP;
		if (skb->protocol == bpf_htons(ETH_P_IP))
			scratch->flag[1] = IpVersionType_4;
		else
			scratch->flag[1] = IpVersionType_6;
		scratch->flag[6] = tuples->dscp;
		if (pid_is_control_plane(skb, &pid_pname))
			return DAE_TC_CONTINUE;
		if (pid_pname)
			__builtin_memcpy(&scratch->flag[2], pid_pname->pname,
					 TASK_COMM_LEN);
		scratch->flag[7] = 1;
		if (link_h_len == ETH_HLEN) {
			scratch->mac_be[2] = bpf_htonl(((__u32)ethh->h_source[0] << 8) |
						  (__u32)ethh->h_source[1]);
			scratch->mac_be[3] = bpf_htonl(((__u32)ethh->h_source[2] << 24) |
						  ((__u32)ethh->h_source[3] << 16) |
						  ((__u32)ethh->h_source[4] << 8) |
						  (__u32)ethh->h_source[5]);
			__builtin_memcpy(scratch->mac, ethh->h_source, 6);
		}

		__s64 s64_ret = route(scratch->flag, tcph,
				      tuples->five.sip.u6_addr32,
				      tuples->five.dip.u6_addr32,
				      scratch->mac_be);

		if (s64_ret < 0) {
			bpf_printk("shot routing: %d", s64_ret);
			return TC_ACT_SHOT;
		}

		outbound = s64_ret & 0xff;
		mark = s64_ret >> 8;
		must = (s64_ret >> 40) & 1;
		routing_epoch_slot = routing_epoch_slot_from_route_result(s64_ret);
		scratch->must_val = must;

		__u8 dscp = tuples->dscp;
		const char *pname_str = NULL;
		__u32 pid_val = 0;

		if (pid_pname) {
			pname_str = pid_pname->pname;
			pid_val = pid_pname->pid;
			handoff_pname = pid_pname->pname;
			handoff_pid = pid_pname->pid;
		}
		__builtin_memcpy(handoff_mac, scratch->mac, 6);

		__u8 *outbound_ptr = &outbound;
		__u32 *mark_ptr = &mark;
		__u8 *must_ptr = &scratch->must_val;

		if (outbound == OUTBOUND_DIRECT && mark == 0 && !must) {
			outbound_ptr = NULL;
			mark_ptr = NULL;
			must_ptr = NULL;
		}

		struct conn_state *tcp_conn = mark_tcp_seen(
			&tuples->five, tcph, false, outbound_ptr, mark_ptr,
			must_ptr, scratch->mac, dscp, pname_str, pid_val,
			routing_epoch_slot);

		if (!tcp_conn) {
			if (outbound == OUTBOUND_DIRECT && mark == 0)
				return DAE_TC_CONTINUE;
			return TC_ACT_SHOT;
		}

#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		__u32 pid = pid_pname ? pid_pname->pid : 0;

		bpf_printk("tcp(wan): from %pI6:%u [PID %u]",
			   tuples->five.sip.u6_addr32,
			   bpf_ntohs(tuples->five.sport), pid);
		bpf_printk("tcp(wan): outbound: %u, %pI6:%u", outbound,
			   tuples->five.dip.u6_addr32,
			   bpf_ntohs(tuples->five.dport));
#endif
	} else {
		// Established TCP: only proxied connections have cached state.
		struct conn_state *tcp_conn = mark_tcp_seen(
			&tuples->five, tcph, false,
			NULL, NULL, NULL, NULL,
			0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN);

		if (!tcp_conn) {
			/* No conn state for an established TCP packet: this is
			 * what every pre-existing flow does after a restart, and
			 * it silently bypasses routing. Keep the
			 * historical passthrough and count it; no per-event
			 * warning, for the same reason as the LAN-ingress twin
			 * above. */
			bump_stat(BPF_STATS_STATELESS_TCP_PASSTHROUGH);
			return DAE_TC_CONTINUE;
		}
		if (!tcp_conn->meta.data.has_routing)
			return DAE_TC_CONTINUE;

		outbound = tcp_conn->meta.data.outbound;
		mark = tcp_conn->meta.data.mark;
		must = tcp_conn->meta.data.must;
		__builtin_memcpy(handoff_mac, tcp_conn->mac, 6);
		__builtin_memcpy(scratch->mac, tcp_conn->mac, 6);
		handoff_pname = (const char *)tcp_conn->pname;
		handoff_pid = tcp_conn->pid;
		routing_epoch_slot =
			routing_epoch_slot_sanitize(tcp_conn->routing_epoch_slot);
		datapath_generation = tcp_conn->datapath_generation;
	}

	if (!wan_egress_needs_control_plane(outbound, mark)) {
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("GO OUTBOUND_DIRECT");
#endif
		skb->mark = mark;
		return DAE_TC_CONTINUE;
	} else if (unlikely(outbound == OUTBOUND_BLOCK)) {
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("SHOT OUTBOUND_BLOCK");
#endif
		return TC_ACT_SHOT;
	}

	if (tcp_state_syn &&
	    !wan_outbound_is_alive(skb, outbound, IPPROTO_TCP,
				   tuples->five.dport))
		return TC_ACT_SHOT;

	struct routing_result routing_result = {};

	fill_routing_result(&routing_result, mark, must, outbound, handoff_mac,
			    tuples->dscp, handoff_pname, handoff_pid,
			    routing_epoch_slot, datapath_generation);
	/* TCP has embedded conn-state routing metadata after the SYN. Keep
	 * handoff for the initial redirect only; established packets are read
	 * from conn_state_map by userspace. */
	if (tcp_state_syn)
		publish_routing_handoff(&tuples->five, &routing_result);

	/* TCP needs redirect_track before the kernel-side handshake completes.
	 * Publishing it later from userspace is too late for the first SYN path.
	 */
	if (prep_redirect_to_control_plane(skb, link_h_len, tuples,
					   ethh, 1))
		return TC_ACT_SHOT;
	skb->cb[0] = TPROXY_MARK;
	skb->cb[1] = tcp_listener_l4proto(tcph);
	return redirect_to_control_plane_egress();
}

static __noinline int
do_tproxy_wan_egress_udp(struct __sk_buff *skb, __u32 link_h_len,
			 struct tuples *tuples, struct ethhdr *ethh,
			 struct udphdr *udph)
{
	struct pid_pname *pid_pname;
	__u8 outbound;
	__u32 mark;
	bool must;
	struct conn_state *udp_conn_state = NULL;
	__u8 mac[6] = {};
	const char *handoff_pname = NULL;
	__u32 handoff_pid = 0;
	__u8 routing_epoch_slot = ROUTING_EPOCH_SLOT_UNKNOWN;
	__u16 datapath_generation = PARAM.datapath_generation;
	bool cached_routing = false;
	__u8 udp_state_status = UDP_CONN_STATE_STATUS_UNAVAILABLE;

	__u32 scratch_key = 0;
	struct wan_egress_route_scratch *scratch =
		bpf_map_lookup_elem(&wan_egress_route_scratch_map, &scratch_key);
	if (!scratch)
		return TC_ACT_SHOT;

	__builtin_memset(scratch, 0, sizeof(*scratch));
	scratch->flag[0] = L4ProtoType_UDP;
	if (skb->protocol == bpf_htons(ETH_P_IP))
		scratch->flag[1] = IpVersionType_4;
	else
		scratch->flag[1] = IpVersionType_6;
	scratch->flag[6] = tuples->dscp;
	if (pid_is_control_plane(skb, &pid_pname))
		return DAE_TC_CONTINUE;

	if (!is_short_lived_udp_traffic(&tuples->five)) {
		udp_conn_state = mark_udp_seen_with_status(
			&tuples->five, false, NULL, NULL, NULL, NULL,
			0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN, &udp_state_status);
		if (udp_conn_state && udp_conn_state->is_wan_ingress_direction)
			return DAE_TC_CONTINUE;

		if (udp_conn_state && udp_conn_state->meta.data.has_routing) {
			outbound = udp_conn_state->meta.data.outbound;
			mark = udp_conn_state->meta.data.mark;
			must = udp_conn_state->meta.data.must;
			__builtin_memcpy(mac, udp_conn_state->mac, 6);
			handoff_pname = (const char *)udp_conn_state->pname;
			handoff_pid = udp_conn_state->pid;
			routing_epoch_slot = routing_epoch_slot_sanitize(
				udp_conn_state->routing_epoch_slot);
			datapath_generation = udp_conn_state->datapath_generation;
			cached_routing = true;
			goto fast_path_skip_routing;
		}
	}

	if (pid_pname) {
		__builtin_memcpy(&scratch->flag[2], pid_pname->pname,
				 TASK_COMM_LEN);
		handoff_pname = pid_pname->pname;
		handoff_pid = pid_pname->pid;
	}
	scratch->flag[7] = 1;
	if (ethh) {
		scratch->mac_be[2] = bpf_htonl(((__u32)ethh->h_source[0] << 8) |
					  (__u32)ethh->h_source[1]);
		scratch->mac_be[3] = bpf_htonl(((__u32)ethh->h_source[2] << 24) |
					  ((__u32)ethh->h_source[3] << 16) |
					  ((__u32)ethh->h_source[4] << 8) |
					  (__u32)ethh->h_source[5]);
		__builtin_memcpy(mac, ethh->h_source, 6);
		__builtin_memcpy(scratch->mac, ethh->h_source, 6);
	}

	__s64 s64_ret = route(scratch->flag, udph,
			      tuples->five.sip.u6_addr32,
			      tuples->five.dip.u6_addr32,
			      scratch->mac_be);

	if (s64_ret < 0) {
		bpf_printk("shot routing: %d", s64_ret);
		return TC_ACT_SHOT;
	}

	outbound = s64_ret & 0xff;
	mark = s64_ret >> 8;
	must = (s64_ret >> 40) & 1;
	routing_epoch_slot = routing_epoch_slot_from_route_result(s64_ret);

fast_path_skip_routing:
	/* last_seen_ns is owned by mark_udp_seen's 1s lazy refresh. Do not
	 * rewrite it here: that undoes the rate-limit and contends the
	 * conn_state_map cacheline on high-PPS WAN flows.
	 */
	if (udp_conn_state && tuples->five.dport != bpf_htons(53) &&
	    (outbound != OUTBOUND_DIRECT || mark != 0 || must)) {
		__builtin_memcpy(udp_conn_state->mac, mac, 6);
		if (pid_pname) {
			__builtin_memcpy(udp_conn_state->pname,
					 pid_pname->pname,
					 TASK_COMM_LEN);
			udp_conn_state->pid = pid_pname->pid;
		}
		udp_conn_state->routing_epoch_slot = routing_epoch_slot;
		udp_conn_state->datapath_generation = datapath_generation;
		union routing_meta _m = build_routing_meta(outbound,
						   mark,
						   must,
						   tuples->dscp);
		publish_routing_meta(&udp_conn_state->meta, _m);
	}

#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
	__u32 pid = pid_pname ? pid_pname->pid : 0;

	bpf_printk("udp(wan): from %pI6:%u [PID %u]", tuples->five.sip.u6_addr32,
		   bpf_ntohs(tuples->five.sport), pid);
	bpf_printk("udp(wan): outbound: %u, %pI6:%u", outbound,
		   tuples->five.dip.u6_addr32, bpf_ntohs(tuples->five.dport));
#endif

	if (!wan_egress_needs_control_plane(outbound, mark))
		return DAE_TC_CONTINUE;
	else if (unlikely(outbound == OUTBOUND_BLOCK))
		return TC_ACT_SHOT;

	if (!cached_routing &&
	    !wan_outbound_is_alive(skb, outbound, IPPROTO_UDP,
				   tuples->five.dport))
		return TC_ACT_SHOT;

	struct routing_result routing_result = {};
	bool handoff_mandatory =
		is_short_lived_udp_traffic(&tuples->five) ||
		udp_state_status != UDP_CONN_STATE_STATUS_EXISTING;

	fill_routing_result(&routing_result, mark, must, outbound, mac,
			    tuples->dscp, handoff_pname, handoff_pid,
			    routing_epoch_slot, datapath_generation);
	if (handoff_mandatory &&
	    publish_routing_handoff(&tuples->five, &routing_result))
		return TC_ACT_SHOT;

	if (prep_redirect_to_control_plane(skb, link_h_len, tuples,
					   ethh, 1))
		return TC_ACT_SHOT;
	skb->cb[0] = TPROXY_MARK;
	skb->cb[1] = IPPROTO_UDP;
	return redirect_to_control_plane_egress();
}

// Per-CPU scratch to stay under 512-byte stack limit across the call chain.
//
// Pass-through returns DAE_TC_CONTINUE, not TC_ACT_OK, so later programs see
// the packet under both classic cls_bpf and TCX multiprogram attachment.
static __noinline int
do_tproxy_wan_egress(struct __sk_buff *skb, __u32 link_h_len,
		     struct parsed_packet *provided_pkt)
{
	if (skb->ingress_ifindex != NOWHERE_IFINDEX)
		return DAE_TC_CONTINUE;

	__u32 scratch_key = 0;
	struct parsed_packet *pkt = provided_pkt;

	if (!pkt) {
		pkt = bpf_map_lookup_elem(&pkt_scratch_map, &scratch_key);
		if (!pkt)
			return TC_ACT_SHOT;

		/* Zero-init for verifier. */
		__builtin_memset(pkt, 0, sizeof(*pkt));
		int ret = parse_packet(skb, link_h_len, pkt);

		if (ret) {
			if (ret < 0) {
				bpf_printk("wan_egress parse error: %d, dropping", ret);
				return TC_ACT_SHOT;
			}
			report_parse_passthrough(ret);
			return DAE_TC_CONTINUE;
		}
	}

	if (pkt->l4proto == IPPROTO_TCP)
		return do_tproxy_wan_egress_tcp(skb, link_h_len, &pkt->tuples,
						&pkt->ethh, &pkt->tcph);
	if (pkt->l4proto == IPPROTO_UDP)
		return do_tproxy_wan_egress_udp(skb, link_h_len, &pkt->tuples,
						&pkt->ethh, &pkt->udph);
	/* parse_packet classifies ICMPv6 as unsupported before reaching here.
	 * The combined egress path uses parse_transport directly to preserve the
	 * LAN role's NDP handling, so report that equivalent classification here. */
	if (pkt->l4proto == IPPROTO_ICMPV6)
		report_parse_passthrough(PARSE_UNSUPPORTED_L4);
	return DAE_TC_CONTINUE;
}

SEC("tc/wan_egress_l2")
int tproxy_wan_egress_l2(struct __sk_buff *skb)
{
	return do_tproxy_wan_egress(skb, 14, NULL);
}

SEC("tc/wan_egress_l3")
int tproxy_wan_egress_l3(struct __sk_buff *skb)
{
	return do_tproxy_wan_egress(skb, 0, NULL);
}

static __always_inline int
do_tproxy_lan_wan_egress(struct __sk_buff *skb, __u32 link_h_len)
{
	__u32 scratch_key = 0;
	struct parsed_packet *pkt =
		bpf_map_lookup_elem(&pkt_scratch_map, &scratch_key);

	if (!pkt)
		return TC_ACT_SHOT;

	int ret = do_tproxy_lan_egress(skb, link_h_len, pkt);

	if (ret != DAE_TC_CONTINUE)
		return ret;
	return do_tproxy_wan_egress(skb, link_h_len, pkt);
}

SEC("tc/lan_wan_egress_l2")
int tproxy_lan_wan_egress_l2(struct __sk_buff *skb)
{
	return do_tproxy_lan_wan_egress(skb, 14);
}

SEC("tc/lan_wan_egress_l3")
int tproxy_lan_wan_egress_l3(struct __sk_buff *skb)
{
	return do_tproxy_lan_wan_egress(skb, 0);
}

SEC("tc/dae0peer_ingress")
int tproxy_dae0peer_ingress(struct __sk_buff *skb)
{
	/* Only packets redirected from wan_egress or lan_ingress have this cb mark.
   */
	if (skb->cb[0] != TPROXY_MARK)
		return TC_ACT_SHOT;

	/* ip rule add fwmark 0x8000000/0x8000000 table 2023
   * ip route add local default dev lo table 2023
   */
	skb->mark = TPROXY_MARK;
	bpf_skb_change_type(skb, PACKET_HOST);

	/* listener_l4proto is stored in skb->cb[1] only when the control-plane
	 * handoff needs an explicit listener assignment (UDP or TCP SYN, including
	 * first fragments that still expose those headers). Established TCP can
	 * return to the stack without bpf_sk_assign.
	 */
	__u8 l4proto = skb->cb[1];

	if (l4proto != 0)
		assign_listener(skb, l4proto);
	return TC_ACT_OK;
}

// load_redirect_tuple_fast returns this code when it cannot safely parse via
// direct packet access and should fall back to bpf_skb_load_bytes.
#define LOAD_REDIRECT_TUPLE_FALLBACK 2

static __always_inline int
load_redirect_tuple_fast(struct __sk_buff *skb,
			 struct redirect_tuple *redirect_tuple)
{
	void *data, *data_end;

	// Pull header data to linear region for direct access.
	// 128 bytes is enough for: ethhdr(14) + iphdr(40) + addresses.
#define REDIRECT_PULL_SIZE 128
	if (bpf_skb_pull_data(skb, REDIRECT_PULL_SIZE))
		return LOAD_REDIRECT_TUPLE_FALLBACK;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return LOAD_REDIRECT_TUPLE_FALLBACK;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + ETH_HLEN;

		if ((void *)(iph + 1) > data_end)
			return LOAD_REDIRECT_TUPLE_FALLBACK;
		// Use IPv4-mapped IPv6 format with ffff marker to match insert side
		redirect_tuple->sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple->sip.u6_addr32[3] = iph->daddr;
		redirect_tuple->dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple->dip.u6_addr32[3] = iph->saddr;
		return 0;
	}
	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6h = data + ETH_HLEN;

		if ((void *)(ipv6h + 1) > data_end)
			return LOAD_REDIRECT_TUPLE_FALLBACK;
		__builtin_memcpy(&redirect_tuple->sip, &ipv6h->daddr,
				 sizeof(redirect_tuple->sip));
		__builtin_memcpy(&redirect_tuple->dip, &ipv6h->saddr,
				 sizeof(redirect_tuple->dip));
		return 0;
	}
	return 1;
}

static __always_inline int
load_redirect_tuple_slow(struct __sk_buff *skb,
			 struct redirect_tuple *redirect_tuple)
{
	int ret;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		// Set ffff marker first for IPv4-mapped IPv6 format
		__u32 ffff_marker = bpf_htonl(0x0000ffff);

		redirect_tuple->sip.u6_addr32[2] = ffff_marker;
		redirect_tuple->dip.u6_addr32[2] = ffff_marker;

		ret = bpf_skb_load_bytes(skb,
					 ETH_HLEN + offsetof(struct iphdr, daddr),
					 &redirect_tuple->sip.u6_addr32[3],
					 sizeof(redirect_tuple->sip.u6_addr32[3]));
		if (ret)
			return ret;
		ret = bpf_skb_load_bytes(skb,
					 ETH_HLEN + offsetof(struct iphdr, saddr),
					 &redirect_tuple->dip.u6_addr32[3],
					 sizeof(redirect_tuple->dip.u6_addr32[3]));
		if (ret)
			return ret;
		return 0;
	}
	if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		ret = bpf_skb_load_bytes(skb,
					 ETH_HLEN + offsetof(struct ipv6hdr, daddr),
					 &redirect_tuple->sip,
					 sizeof(redirect_tuple->sip));
		if (ret)
			return ret;
		ret = bpf_skb_load_bytes(skb,
					 ETH_HLEN + offsetof(struct ipv6hdr, saddr),
					 &redirect_tuple->dip,
					 sizeof(redirect_tuple->dip));
		if (ret)
			return ret;
		return 0;
	}
	return 1;
}

static __always_inline int
load_redirect_tuple(struct __sk_buff *skb,
		    struct redirect_tuple *redirect_tuple)
{
	int ret = load_redirect_tuple_fast(skb, redirect_tuple);

	if (ret == LOAD_REDIRECT_TUPLE_FALLBACK)
		return load_redirect_tuple_slow(skb, redirect_tuple);
	return ret;
}

/* reply_publisher_matches reports whether the reply packet in flight was sent
 * by the host/mac pair the stored binary binding belongs to: the reply's L2
 * source is the mac the binding routes back to, and its L2 destination is the
 * peer it was published for. This mirrors the publisher test the forward path
 * applies (publish_redirect_track_for_packet compares ifindex / from_wan /
 * smac); the reply path has no forward ifindex to compare against, because
 * every reply arrives on the same dae0 ingress hook.
 *
 * An unreadable L2 header is reported as "not the publisher" on purpose: the
 * conservative failure of this test is to stop refreshing the entry, which
 * lets the userspace janitor expire it, whereas the optimistic failure would
 * hand a frozen binding an unlimited lease and make the 2s window
  * unrecoverable .
 */
static __always_inline bool
reply_publisher_matches(struct __sk_buff *skb,
			const struct redirect_entry *redirect_entry)
{
	struct ethhdr eth;

	/* Read the L2 header with bpf_skb_load_bytes rather than through
	 * skb->data: the header is at L2 offset 0 on this hook, and this way the
	 * test is independent of both the read being preceded by a pull and of
	 * how skb->data is interpreted for the packet's protocol. */
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)))
		return false;
	return mac6_equal(redirect_entry->smac, eth.h_source) &&
	       mac6_equal(redirect_entry->dmac, eth.h_dest);
}

SEC("tc/dae0_ingress")
int tproxy_dae0_ingress(struct __sk_buff *skb)
{
	struct redirect_tuple redirect_tuple = {};
	int ret;

	ret = load_redirect_tuple(skb, &redirect_tuple);
	if (ret)
		return TC_ACT_OK;
	struct redirect_entry *redirect_entry =
		bpf_map_lookup_elem(&redirect_track, &redirect_tuple);

	if (!redirect_entry)
		return TC_ACT_OK;

	/* Only the publisher of the binding may extend its lease. Refreshing
	 * last_seen_ns for every packet that matched the tuple let a rejected
	 * competitor keep its victim's binding frozen forever: the rejection on
	 * the forward path deliberately does not refresh, but the competitor's
	 * own replies did, so the staleness window that is supposed to release
	 * the binding never elapsed and the flow stayed on the winner's path
	 * for good. Keeping the refresh tied to the publisher is what makes the
	 * window mean "the winner has been silent for that long", which is
	 * exactly when the competitor is allowed to take over. */
	if (reply_publisher_matches(skb, redirect_entry))
		redirect_entry->last_seen_ns = bpf_ktime_get_ns();

	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
			    redirect_entry->dmac, sizeof(redirect_entry->dmac),
			    0);
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
			    redirect_entry->smac, sizeof(redirect_entry->smac),
			    0);
	__u32 type = redirect_entry->from_wan ? PACKET_HOST : PACKET_OTHERHOST;

	bpf_skb_change_type(skb, type);
	__u64 flags = redirect_entry->from_wan ? BPF_F_INGRESS : 0;

	return bpf_redirect(redirect_entry->ifindex, flags);
}

struct get_real_comm_ctx {
	char *arg_buf;
	u8 l;
};

static int __noinline get_real_comm_loop_cb(__u32 index, void *data)
{
	/*
	* For string like: /usr/lib/sddm/sddm-helper --socket /tmp/sddm-auth1
	* We extract "sddm-helper" from it.
	*/
	struct get_real_comm_ctx *ctx = (struct get_real_comm_ctx *)data;

	if (index >= MAX_ARG_LEN) // always false, just to make verifier happy
		return 1;
	if (unlikely(ctx->arg_buf[index] == '/'))
		ctx->l = index + 1;
	if (unlikely(ctx->arg_buf[index] == ' ' ||
		     ctx->arg_buf[index] == '\0')) {
		// Write to dst.
		ctx->arg_buf[index] = '\0';
		return 1;
	}
	return 0;
}

/// Parse command line arguments to get the real command name and tgid.
static __always_inline int get_pid_pname(struct pid_pname *pid_pname)
{
	int ret;

	// Populate tgid and timestamp first
	pid_pname->last_seen_ns = bpf_ktime_get_ns();
	pid_pname->pid = bpf_get_current_pid_tgid() >> 32;

	if (!PARAM.has_bpf_get_current_task) {
		if (bpf_get_current_comm(&pid_pname->pname, sizeof(pid_pname->pname)))
			pid_pname->pname[0] = '\0';
		return 0;
	}

	// Get pointer to args string.
	struct task_struct *task = (void *)bpf_get_current_task();
	char *args = (void *)BPF_CORE_READ(task, mm, arg_start);

	// Read args to buffer.
	char arg_buf[MAX_ARG_LEN]; // Allocate it out of ctx to pass CO-RE
	struct get_real_comm_ctx ctx = {};

	ctx.arg_buf = arg_buf;
	ret = bpf_core_read_user_str(arg_buf, MAX_ARG_LEN, args);
	if (unlikely(ret < 0)) {
		bpf_printk(
			"failed to read process name: bpf_core_read_user_str: %d",
			ret);
		return ret;
	}

	// Find range of command name.
	ret = bpf_loop(MAX_ARG_LEN, get_real_comm_loop_cb, &ctx, 0);
	if (unlikely(ret < 0))
		return ret;

	u8 offset = ctx.l;

	for (u8 i = 0; i < TASK_COMM_LEN; i++) {
		if (offset + i < MAX_ARG_LEN && arg_buf[offset + i] != '\0') {
			pid_pname->pname[i] = arg_buf[offset + i];
		} else {
			pid_pname->pname[i] = '\0';
			break;
		}
	}

	return 0;
}

static __always_inline int _update_map_elem_by_cookie(const __u64 cookie)
{
	if (unlikely(!cookie)) {
		bpf_printk("zero cookie");
		return -EINVAL;
	}
	struct pid_pname *existing = bpf_map_lookup_elem(&cookie_pid_map, &cookie);

	if (existing) {
		// Cookie to pid mapping already exists.
		existing->last_seen_ns = bpf_ktime_get_ns();
		return 0;
	}

	int ret;
	// Build value.
	struct pid_pname val = { 0 };

	ret = get_pid_pname(&val);
	if (ret)
		return ret;

	// Update map.
	ret = bpf_map_update_elem(&cookie_pid_map, &cookie, &val, BPF_ANY);
	if (unlikely(ret))
		return ret;

#ifdef __PRINT_SETUP_PROCESS_CONNNECTION
	bpf_printk("setup_mapping: %llu -> %s (%d)", cookie, val.pname,
		   val.pid);
#endif
	return 0;
}

static __always_inline int update_map_elem_by_cookie(const __u64 cookie)
{
	int ret;

	ret = _update_map_elem_by_cookie(cookie);
	if (ret) {
		// Fallback to only write pid to avoid loop due to packets sent by dae.
		struct pid_pname val = { 0 };

		val.last_seen_ns = bpf_ktime_get_ns();
		val.pid = bpf_get_current_pid_tgid() >> 32;
		bpf_map_update_elem(&cookie_pid_map, &cookie, &val, BPF_ANY);
		return ret;
	}
	return 0;
}

// Create cookie to pid, pname mapping.
SEC("cgroup/sock_create")
int tproxy_wan_cg_sock_create(struct bpf_sock *sk)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(sk));
	return 1;
}

// Remove cookie to pid, pname mapping.
SEC("cgroup/sock_release")
int tproxy_wan_cg_sock_release(struct bpf_sock *sk)
{
	__u64 cookie = bpf_get_socket_cookie(sk);

	if (unlikely(!cookie)) {
		bpf_printk("zero cookie");
		return 1;
	}
	bpf_map_delete_elem(&cookie_pid_map, &cookie);
	return 1;
}

SEC("cgroup/connect4")
int tproxy_wan_cg_connect4(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/connect6")
int tproxy_wan_cg_connect6(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/sendmsg4")
int tproxy_wan_cg_sendmsg4(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/sendmsg6")
int tproxy_wan_cg_sendmsg6(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

#include "include/tcp_offload.h"

// tcp_offload_redirect is the stream-verdict (RX path) program for the
// fast_sock SOCKHASH. When a socket registered by the Go control plane
// receives data, this program redirects it to the peer relay socket's egress
// path (i.e. the peer socket transmits it), splicing the pair in-kernel.
//
// The upstream sockmap fast redirect used an sk_msg program with
// BPF_F_INGRESS (delivering written data into the peer receive queue), which
// never transmits bytes for a local<->remote relay pair; this sk_skb +
// egress-redirect design matches kernel selftest semantics instead.
//
// bpf_sk_redirect_hash returns SK_DROP when the key is not found, so a miss
// must be turned into SK_PASS before calling the helper or the packet would
// be silently dropped.
SEC("sk_skb/tcp_offload_redirect")
int tcp_offload_redirect(struct __sk_buff *skb)
{
	struct tuples_key peer_key = {};

	// Key layout must match Go's makeTuplesKey(remote, local, TCP):
	// sip=remote, dip=local, sport=remote_port(BE), dport=local_port(BE).
	// __sk_buff.remote_port carries the network-order port in the high 16
	// bits on little-endian targets (convert_skb_access LSH 16);
	// local_port is host byte order.
	peer_key.l4proto = IPPROTO_TCP;
	peer_key.sport = tcp_offload_remote_port(skb->remote_port);
	peer_key.dport = bpf_htons((__u16)skb->local_port);
	if (skb->family == AF_INET) {
		peer_key.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		peer_key.sip.u6_addr32[3] = skb->remote_ip4;
		peer_key.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		peer_key.dip.u6_addr32[3] = skb->local_ip4;
	} else if (skb->family == AF_INET6) {
		__builtin_memcpy(&peer_key.sip, skb->remote_ip6,
				 IPV6_BYTE_LENGTH);
		__builtin_memcpy(&peer_key.dip, skb->local_ip6, IPV6_BYTE_LENGTH);
	} else {
		return SK_PASS;
	}

	// Backlog fuse: a paused key passes data through to the userspace
	// fallback. The fast_sock entry stays registered so the kernel keeps
	// draining already-redirected skbs from the peer's egress retry queue.
	if (bpf_map_lookup_elem(&tcp_offload_pause, &peer_key))
		return SK_PASS;

	// Pre-check: bpf_sk_redirect_hash returns SK_DROP when the key is not
	// found, which would silently discard the packet. Pass instead. The
	// lookup returns a referenced socket that must be released before the
	// program exits (the redirect helper itself does not take a reference).
	{
		struct bpf_sock *peer =
			bpf_map_lookup_elem(&fast_sock, &peer_key);
		if (!peer)
			return SK_PASS;
		bpf_sk_release(peer);
	}

	// flags == 0 selects the egress path: the peer socket sends the data.
	// The helper returns SK_DROP when the key vanished between the pre-check
	// lookup above and this call (userspace teardown deletes keys after
	// pausing), or on any other redirect failure. Dropping the skb would
	// lose the packet, so translate every outcome into SK_PASS: a successful
	// redirect has already marked the skb, and a failed one is handed to
	// the userspace fallback path. No further reference accounting is
	// involved here: the helper resolves the redirect target from the map
	// and records it in the skb (validated later under RCU when the verdict
	// runs), so the pre-check's released reference stays balanced.
	bpf_sk_redirect_hash(skb, &fast_sock, &peer_key, 0);
	return SK_PASS;
}

SEC("license") const char __license[] = "Dual BSD/GPL";

/* tcp_offload_sent_account records, per reversed four-tuple, the bytes that
 * skb_send_sock pushes into a peer socket's send path. The key layout
 * must match tcp_offload_redirect's peer_key so the Go session can look up
 * both directions with its registered keys. Userspace picks the attach
 * site per kernel (see tcp_offload_hook.go): fentry on the outer wrapper
 * when only it is verified, or the kprobe variant on the shared inner
 * __skb_send_sock when LTO can bypass the wrapper.
 *
 * NOTE: the hook must sit on skb_send_sock, not skb_send_sock_locked.
 * The sockmap verdict egress path is sk_psock_verdict_apply ->
 * sk_psock_skb_redirect -> sk_psock_handle_skb -> skb_send_sock
 * (net/core/skmsg.c); skb_send_sock_locked's only caller in the whole
 * kernel is net/xfrm/espintcp.c, so a hook placed there never fires on
 * our redirect path and the sent counters stay empty (verified against
 * v6.12 and v6.17 sources). Both functions are identical one-line
 * tail-call wrappers into __skb_send_sock with the same first four
 * arguments, so the BPF_PROG signature below is unchanged.
 *
 * A successful attach does not prove this wrapper executes. LTO kernels
 * can bypass it and call __skb_send_sock directly; the E2E sent/inflow
 * assertions must still pass before relying on accounting on that kernel.
 *
 * An earlier EBUSY when attaching to skb_send_sock on 6.12/6.17/6.18 was
 * an attachment-conflict signal, not a function-shape artifact: the
 * kernel-side EBUSY conditions for fentry link_create are an EXT/freplace
 * program on the target, the same prog linked twice, or an existing
 * direct call on the target function (a trampoline with a different key,
 * or any other ftrace direct-call user); see kernel/bpf/trampoline.c
 * __bpf_trampoline_link_prog and kernel/trace/ftrace.c
 * register_ftrace_direct. The actual conflict was the reload-leftover
 * fentry link, fixed at the root by the per-bpfObjects link registry
 * (reuse across reload generations), so re-attaching to skb_send_sock
 * should now succeed.
 *
 * Accounting caveat: fentry fires on function entry, so skbs requeued via
 * the EAGAIN retry path in sk_psock_handle_skb (!sock_writeable) are
 * counted once per attempt. Under congestion this over-estimates "sent"
 * and delays fuse engagement slightly — the conservative direction
 * relative to a dead counter, accepted deliberately.
 *
 * KPROBE FALLBACK: on kernels without CONFIG_DYNAMIC_FTRACE (trimmed
 * router builds such as ImmortalWrt), functions carry no mcount NOP
 * entry, so fentry attach goes through bpf_arch_text_poke, which requires
 * the entry to be a 5-byte NOP and returns EBUSY for tail-call wrappers
 * whose entry is `jmp`. The kprobe variant attaches at any instruction
 * boundary and is selected by the Go side when the fentry attach fails. */
static __always_inline void
tcp_offload_sent_account_body(struct sk_buff *skb, int len)
{
	struct tuples_key key = {};
	__u64 *v;

	if (!tcp_offload_skb_key(skb, &key))
		return;

	v = bpf_map_lookup_elem(&tcp_offload_sent, &key);
	if (v) {
		__sync_fetch_and_add(v, len);
	} else {
		__u64 init = len;

		bpf_map_update_elem(&tcp_offload_sent, &key, &init, BPF_ANY);
	}
}

SEC("fentry/skb_send_sock")
int BPF_PROG(tcp_offload_sent_account, struct sock *sk, struct sk_buff *skb,
	     int offset, int len)
{
	tcp_offload_sent_account_body(skb, len);
	return 0;
}

SEC("kprobe/skb_send_sock")
int BPF_KPROBE(tcp_offload_sent_account_kprobe, struct sock *sk,
	       struct sk_buff *skb, int offset, int len)
{
	tcp_offload_sent_account_body(skb, len);
	return 0;
}
