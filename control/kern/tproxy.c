// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

// +build ignore

// Disable implicit CO-RE from vmlinux.h to bypass bad relocation caused by GCC 15 DTE stripping UAPI structs.
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
// bpf_timer removed: using timestamp-based lazy deletion instead
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
#define MAX_LPM_SIZE 2048000
#define MAX_LPM_NUM (MAX_MATCH_SET_LEN + 8)
#define MAX_DST_MAPPING_NUM (65536 * 2)
#define MAX_COOKIE_PID_PNAME_MAPPING_NUM (65536)
#define MAX_DOMAIN_ROUTING_NUM 65536
#define MAX_ARG_LEN 128
#define IPV6_MAX_EXTENSIONS 8  // Increased from 4 to allow legitimate extension header chains while preventing abuse

#define ipv6_optlen(p) (((p)+1) << 3)

#define TPROXY_MARK 0x8000000

#define NDP_REDIRECT 137

// Param keys:
static const __u32 zero_key;
static const __u32 one_key = 1;
static const __u32 two_key = 2;

// Outbound Connectivity Map:

// outbound_connectivity_query is deprecated. Using direct index calculation for
// ARRAY map to achieve O(1) lookup performance.
// Key format: outbound_id * 6 + domain * 2 + ipversion
// where: domain (0=TCP, 1=DNS UDP, 2=data UDP), ipversion (0=IPv4, 1=IPv6)

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
	__u64 last_seen_ns;  // Timestamp for userspace janitor cleanup
};

// redirect_track: Track redirect entries for reply traffic routing.
//
// Design rationale:
// - Uses HASH with timestamp-based cleanup by userspace janitor.
// - Key is {sip, dip} only (no ports), shared by all connections between same IP pair.
// - last_seen_ns is updated on each access (lookup and update) for accurate TTL.
// - Userspace janitor removes entries older than REDIRECT_TRACK_TTL.
//
// Note: Previously used LRU_HASH, but LRU is unsuitable because:
// - LRU tracks "last access time" not "entry age"
// - Long-lived connections (e.g., SSH) cause their entries to never be evicted
// - This prevents cleanup of other IP pairs' entries
// - HASH + TTL provides predictable expiration behavior.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct redirect_tuple);
	__type(value, struct redirect_entry);
	__uint(max_entries, 65536);
} redirect_track SEC(".maps");

struct ip_port {
	union ip6 ip;
	__be16 port;
};

// routing_result: Routing decision result structure.
// NOTE: This struct is used by userspace caches and the first-packet routing
// fallback handoff map. Conn-state maps remain the authoritative datapath cache.
struct routing_result {
	__u32 mark;
	__u8 must;
	__u8 mac[6];
	__u8 outbound;
	__u8 pname[TASK_COMM_LEN];
	__u32 pid;
	__u8 dscp;
};

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
	__u16 padding2;
	// dae_socket_mark is set on dae's own sockets (Anyfrom pool) to identify them.
	// When bpf_sk_lookup_* finds a socket, we check this mark to skip dae's own sockets.
	// This prevents false positives in NAT loopback detection for transparent proxying.
	__u32 dae_socket_mark;
};

/* Use const volatile for cilium/ebpf v0.20.0 compatibility.
 * This ensures the variable is placed in .rodata section and
 * can be rewritten from userspace via RewriteConstants. */
const volatile struct dae_param PARAM = {};

/* fast_sock map and sk_msg programs are preserved here strictly for ABI compatibility
 * with Go's generated bpf2go code (bpf_stub.go) and tcp_offload_linux.go.
 * BPF_PROG_TYPE_SOCK_OPS + BPF_PROG_TYPE_SK_MSG (bpf_msg_redirect_hash) combination
 * has been proven to cause Kernel Panic. We use TC-based redirect instead.
 * The Go side will still interact with these stubs, but they do nothing in the kernel.
 */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct tuples_key);
	__type(value, __u64);
	__uint(max_entries, 1);
} fast_sock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct tuples_key);
	__type(value, struct routing_handoff_entry);
	__uint(max_entries, 65536);
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
	bool not ; // A subrule flag (this is not a match_set flag).
	enum MatchType type;
	__u8 outbound; // User-defined value range is [0, 252].
	bool must;
	__u32 mark;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct match_set);
	__uint(max_entries, MAX_MATCH_SET_LEN);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} routing_map SEC(".maps");

// Runtime routing metadata.
// key=0 => active routing rules length in routing_map.
// Userspace updates this after rebuilding routing rules so route() can avoid
// scanning up to MAX_MATCH_SET_LEN on every packet.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} routing_meta_map SEC(".maps");

struct domain_routing {
	__u32 bitmap[MAX_MATCH_SET_LEN / 32];
};

// domain_routing_map: Cache domain → routing bitmap mappings.
//
// Design rationale:
// - Changed from LRU_HASH to HASH.
// - 128-byte value size makes LRU operations extremely expensive (copies on every access).
// - Domain cache should be TTL-based or explicitly managed, not access-time-based eviction.
// - Userspace manages cleanup via TTL/explicit deletion for semantic correctness.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __be32[4]);
	__type(value, struct domain_routing);
	__uint(max_entries, MAX_DOMAIN_ROUTING_NUM);
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct pid_pname);
	__uint(max_entries, MAX_COOKIE_PID_PNAME_MAPPING_NUM);
} cookie_pid_map SEC(".maps");

// udp_conn_state: Track UDP connection state and cached routing decision.
//
// Design rationale (Scheme3 - Embedded Design):
// - Routing result is embedded directly in conn state to ensure consistency.
// - Single source of truth: no separate routing_tuples_map to sync.
// - This eliminates orphaned entries and simplifies cascade cleanup.
// - Preserved across in-process reload via userspace BPF object handoff.
// - Userspace loaders may disable bpffs pinning on cold start to avoid inheriting
//   stale conn-state from a previous process.
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
	/* Publish routing only after side fields (mac/pname/pid) are ready. */
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

struct udp_conn_state {
	// For each flow (echo symmetric path), note the original flow direction.
	// Mark as true if traffic go through wan ingress.
	// For traffic from lan that go through wan ingress, dae parse them in lan egress
	bool is_wan_ingress_direction;

	// Last seen timestamp in nanoseconds (bpf_ktime_get_ns()).
	// Userspace janitor periodically cleans up expired entries.
	__u64 last_seen_ns;

	// Embedded routing decision result for this flow.
	// This avoids a separate routing_tuples_map lookup and ensures consistency.
	union routing_meta meta;
	__u8 mac[6];               // Next hop MAC for redirected packets
	__u8 padding[2];           // Alignment
	__u8 pname[TASK_COMM_LEN]; // Process name (for WAN egress; empty for LAN)
	__u32 pid;                 // Process ID (for WAN egress; 0 for LAN)
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DST_MAPPING_NUM);
	__type(key, struct tuples_key);
	__type(value, struct udp_conn_state);
	__uint(pinning, LIBBPF_PIN_BY_NAME);  // Loader may override pinning on cold start.
} udp_conn_state_map SEC(".maps");

// tcp_conn_state: Track TCP connection state and cached routing decision.
//
// Design rationale (Scheme3 - Embedded Design):
// - Routing result is embedded directly in conn state to ensure consistency.
// - Single source of truth: no separate routing_tuples_map to sync.
// - This eliminates orphaned entries and simplifies cascade cleanup.
// - Preserved across in-process reload via userspace BPF object handoff.
// - Userspace loaders may disable bpffs pinning on cold start to avoid inheriting
//   stale conn-state from a previous process.
struct tcp_conn_state {
	// For each flow (echo symmetric path), note the original flow direction.
	// Mark as true if traffic go through wan ingress.
	bool is_wan_ingress_direction;

	// Connection state: 0 = active, 1 = closing (FIN/RST seen)
	// When in closing state, userspace janitor will clean up this entry.
	__u8 state;

	// Last seen timestamp in nanoseconds (bpf_ktime_get_ns()).
	// Userspace janitor periodically cleans up expired entries.
	__u64 last_seen_ns;

	// Embedded routing decision result for this flow.
	// This avoids a separate routing_tuples_map lookup and ensures consistency.
	union routing_meta meta;
	__u8 mac[6];               // Next hop MAC for redirected packets
	__u8 padding[2];           // Alignment
	__u8 pname[TASK_COMM_LEN]; // Process name (for WAN egress; empty for LAN)
	__u32 pid;                 // Process ID (for WAN egress; 0 for LAN)
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DST_MAPPING_NUM);
	__type(key, struct tuples_key);
	__type(value, struct tcp_conn_state);
	__uint(pinning, LIBBPF_PIN_BY_NAME);  // Loader may override pinning on cold start.
} tcp_conn_state_map SEC(".maps");

// bpf_stats: Map statistics for monitoring and robustness.
// key=0: udp_conn_state_map overflow count (when bpf_map_update_elem fails with -E2BIG)
// key=1: tcp_conn_state_map overflow count
// Userspace reads these counters to detect map pressure and trigger alerts.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 2);
} bpf_stats_map SEC(".maps");

enum bpf_stats_key {
	BPF_STATS_UDP_CONN_OVERFLOW = 0,
	BPF_STATS_TCP_CONN_OVERFLOW = 1,
};

// DAE event system: Structured events for monitoring and observability.
// Events are delivered to userspace via ring buffer for efficient processing.
enum dae_event_type {
	DAE_EVENT_BLOCKED = 0,       // Connection blocked (OUTBOUND_BLOCK)
	DAE_EVENT_UDP_CONN_OVERFLOW = 1, // UDP conn state map overflow
	DAE_EVENT_TCP_CONN_OVERFLOW = 2, // TCP conn state map overflow
};

struct dae_event {
	__u64 timestamp;    // Event timestamp (nanoseconds since boot)
	__u32 type;         // Event type (enum dae_event_type)
	__u32 pid;          // Process ID (0 if not available)
	__u8 pname[16];     // Process name (empty if not available)
	__u8 outbound;       // Outbound ID (for routing/block events)
	__u8 l4proto;       // Layer 4 protocol
	__u8 pad[2];
	__u32 sip[4];       // Source IP (IPv4-mapped IPv6 format)
	__u32 dip[4];       // Destination IP (IPv4-mapped IPv6 format)
	__u16 sport;        // Source port
	__u16 dport;        // Destination port
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

// parse_transport_ctx stores header pointers for parsing.
// This struct is designed to be used with scratch maps to avoid stack pressure.
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

// send_dae_event sends a structured event to the userspace via ring buffer.
// Returns: 0 on success, negative error code on failure.
static __always_inline int
send_dae_event(__u32 type, __u32 pid, const char *pname, __u8 outbound,
	       __u8 l4proto, const __u32 *sip, const __u32 *dip,
	       __u16 sport, __u16 dport)
{
	struct dae_event e = {};

	e.timestamp = bpf_ktime_get_ns();
	e.type = type;
	e.pid = pid;
	e.outbound = outbound;
	e.l4proto = l4proto;
	e.sport = sport;
	e.dport = dport;

	if (pname)
		__builtin_memcpy(e.pname, pname, 16);

	if (sip)
		__builtin_memcpy(e.sip, sip, 16);

	if (dip)
		__builtin_memcpy(e.dip, dip, 16);

	return bpf_ringbuf_output(&event_ringbuf, &e, sizeof(e), 0);
}

static __always_inline __u8 ipv4_get_dscp(const struct iphdr *iph)
{
	return (iph->tos & 0xfc) >> 2;
}

static __always_inline __u8 ipv6_get_dscp(const struct ipv6hdr *ipv6h)
{
	const __u8 *version_and_tc = (const __u8 *)ipv6h;

	/* Extract DSCP from the raw IPv6 version / traffic-class bytes instead of
	 * relying on bitfields. This keeps the result stable across kernels/BTF
	 * layouts and matches the on-wire header layout directly:
	 *   byte0 low nibble  = traffic class bits [7:4]
	 *   byte1 high 2 bits = traffic class bits [3:2]
	 */
	return ((version_and_tc[0] & 0x0f) << 2) | (version_and_tc[1] >> 6);
}

static __always_inline void
get_tuples(const struct __sk_buff *skb, struct tuples *tuples,
	   const struct iphdr *iph, const struct ipv6hdr *ipv6h,
	   const struct tcphdr *tcph, const struct udphdr *udph, __u8 l4proto)
{
	__builtin_memset(tuples, 0, sizeof(*tuples));
	tuples->five.l4proto = l4proto;

	// Check IP version by examining the protocol headers.
	// Since both iph and ipv6h are stack-allocated (non-NULL pointers),
	// we must check the version field rather than pointer validity.
	if (iph->version == 4) {
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
		return true;
	default:
		return false;
	}
}

#define PARSE_FRAGMENT 2

static __always_inline __u8
tcp_listener_l4proto(const struct tcphdr *tcph)
{
	return tcph && tcph->syn && !tcph->ack ? IPPROTO_TCP : 0;
}

// parse_transport_fast implements direct packet access using bpf_skb_pull_data
// to linearize non-linear data regions, then accesses headers via pointer arithmetic.
//
// Key principles for BPF direct access:
// 1. Use bpf_skb_pull_data to ensure header data is in linear region
// 2. Use pointer arithmetic on skb->data to get header pointers
// 3. Always check (ptr + 1) <= data_end before dereferencing
// 4. Boundary check failures return -1 to fall back to slow path;
//    malformed packets (e.g. ihl < 5) return -EFAULT to drop immediately.
//
// Returns: 0 on success, -1 to fall back to slow path, positive on error,
//          -EFAULT for unrecoverable malformed packets.
//
// Keep this inline so scratch-map pointers don't cross BPF-to-BPF subprogram
// boundaries on older verifiers.
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

	// Optimized pull strategy: pull minimal headers upfront.
	// 128 bytes covers: ethhdr(14) + IPv4 hdr(20) + TCP hdr(20) + options.
	// This is a compromise between performance and verifier complexity.
	// Larger pull sizes cause verifier instruction explosion on 6.12+.
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
		// Direct assignment is more efficient than memcpy for small arrays
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
		if (iph_ptr->ihl < 5)
			return -EFAULT;

		// Copy base IP fields first: saddr/daddr must be valid in ctx->iph
		// so that get_tuples() works correctly even when we return
		// PARSE_FRAGMENT below (before the normal copy path).
		iph->version = iph_ptr->version;
		iph->ihl = iph_ptr->ihl;
		iph->protocol = iph_ptr->protocol;
		iph->saddr = iph_ptr->saddr;
		iph->daddr = iph_ptr->daddr;
		*ihl = iph_ptr->ihl;
		*l4proto = iph_ptr->protocol;

		__u32 ip_hdr_len = iph_ptr->ihl * 4;
		__u32 l4_offset = offset + ip_hdr_len;

		// Preserve the historical behavior for the first fragment, which still
		// carries the transport header and can participate in normal routing.
		// Only non-initial fragments lack the L4 header and must fall back to
		// the kernel stack for reassembly.
		__u16 frag_off = bpf_ntohs(iph_ptr->frag_off);

		if ((frag_off & 0x1FFF) != 0)
			return PARSE_FRAGMENT;

		// L4 parsing: simplified with single boundary check
		switch (iph->protocol) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph_ptr = data + l4_offset;

			if ((void *)(tcph_ptr + 1) > data_end)
				return -1;
			tcph->source = tcph_ptr->source;
			tcph->dest = tcph_ptr->dest;
			tcph->seq = tcph_ptr->seq;
			tcph->ack_seq = tcph_ptr->ack_seq;
			tcph->doff = tcph_ptr->doff;
			tcph->rst = tcph_ptr->rst;
			tcph->syn = tcph_ptr->syn;
			tcph->fin = tcph_ptr->fin;
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
			return 1;
		}
	}

	if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6h_ptr = data + offset;

		if ((void *)(ipv6h_ptr + 1) > data_end)
			return -1;

		ipv6h->version = ipv6h_ptr->version;
		ipv6h->nexthdr = ipv6h_ptr->nexthdr;
		ipv6h->payload_len = ipv6h_ptr->payload_len;
		// Copy IPv6 addresses - use loop for 128-bit addresses
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

		// Simplified IPv6 extension header handling
		// Unroll loop to reduce verifier complexity
		__u8 nexthdr = ipv6h_ptr->nexthdr;
		const __u8 *ext_hdr;

		// Extension header iteration (unrolled for verifier)
		for (int i = 0; i < IPV6_MAX_EXTENSIONS; i++) {
			if (nexthdr == IPPROTO_NONE)
				return -EFAULT;
			if (nexthdr == IPPROTO_FRAGMENT) {
				// Mirror the stable pre-c0a0f1 behavior: keep parsing the first
				// fragment, which still carries the transport header, but pass
				// non-initial fragments back to the kernel stack.
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

			nexthdr = ext_hdr[0];
			offset += ipv6_optlen(ext_hdr[1]);
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
			tcph->doff = tcph_ptr->doff;
			tcph->rst = tcph_ptr->rst;
			tcph->syn = tcph_ptr->syn;
			tcph->fin = tcph_ptr->fin;
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
			return 1;
		}
	}

	return 1;
}

// Slow path using bpf_skb_load_bytes for extreme cases:
// - Packets with large IPv6 extension headers (> 512 bytes)
// - Memory allocation failure in fast path
// - Non-linear data that couldn't be pulled
//
// Keep this inline so scratch-map pointers don't cross BPF-to-BPF subprogram
// boundaries on older verifiers.
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
			return 1;
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
		if (iph->ihl < 5)
			return -EFAULT;
		*ihl = iph->ihl;
		*l4proto = iph->protocol;

		// Preserve the stable routing behavior for the first fragment, which
		// still exposes the transport header. Only non-initial fragments need
		// to fall back to the kernel for reassembly.
		__u16 frag_off = bpf_ntohs(iph->frag_off);

		if ((frag_off & 0x1FFF) != 0)
			return PARSE_FRAGMENT;

		offset += iph->ihl * 4;

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
			return 1;
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
				// Preserve the stable first-fragment behavior while letting
				// non-initial fragments pass through for kernel reassembly.
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

			// Read next header and extension header length
			ret = bpf_skb_load_bytes(skb, offset, &nexthdr, 1);
			if (ret)
				return -EFAULT;

			__u8 hdr_ext_len = 0;

			ret = bpf_skb_load_bytes(skb, offset + 1, &hdr_ext_len,
						 sizeof(hdr_ext_len));
			if (ret)
				return -EFAULT;

			__u32 ext_len = ipv6_optlen(hdr_ext_len);

			// Skip the direct access boundary check for extension headers.
			// bpf_skb_load_bytes (used below) can handle non-linear data and
			// will return an error if the data truly doesn't exist.
			// The check using data_end (linear region only) would incorrectly
			// reject valid packets with extension headers in non-linear regions.

			offset += ext_len;
		}

		if (is_extension_header(nexthdr))
			return -EFAULT;  // Too many extension headers - drop as suspicious

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
			return 1;
		}
		return 0;
	}

	return 1;
}

// Main entry point - tries fast path first, falls back to slow path.
// Returns: 0 on success, positive on error.
//
// Keep this inline so scratch-map pointers don't cross BPF-to-BPF subprogram
// boundaries on older verifiers. parse_transport_ctx itself already lives in a
// scratch map, so inlining does not reintroduce the old large stack object.
static __always_inline int
parse_transport(struct __sk_buff *skb, __u32 link_h_len,
		struct parse_transport_ctx *ctx)
{
	int ret = parse_transport_fast(skb, link_h_len, ctx);

	if (ret == -1) {
		// Fast path failed (pull failed or headers too large),
		// fall back to slow path using bpf_skb_load_bytes.
		return parse_transport_slow(skb, link_h_len, ctx);
	}
	return ret;
}

struct lan_ingress_parsed {
	struct ethhdr ethh;
	struct tuples tuples;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 l4proto;
	__u8 listener_l4proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct lan_ingress_parsed);
	__uint(max_entries, 1);
} lan_ingress_scratch_map SEC(".maps");

static __always_inline int
parse_lan_ingress_packet(struct __sk_buff *skb, u32 link_h_len,
			 struct lan_ingress_parsed *out)
{
	__u32 scratch_key = 0;
	struct parse_transport_ctx *ctx =
		bpf_map_lookup_elem(&parse_ctx_scratch_map, &scratch_key);

	if (!ctx)
		return -EFAULT;

	int ret = parse_transport(skb, link_h_len, ctx);

	// Fatal error: drop immediately, no context to copy.
	if (ret < 0)
		return ret;
	if (ctx->l4proto == IPPROTO_ICMPV6)
		return 1;

	// Always populate out with whatever IP context was parsed.
	// PARSE_FRAGMENT still leaves a valid IP tuple behind, which keeps callers
	// and diagnostics aligned without forcing a control-plane redirect.
	__builtin_memset(out, 0, sizeof(*out));
	out->ethh = ctx->ethh;
	out->tcph = ctx->tcph;
	out->udph = ctx->udph;
	out->l4proto = ctx->l4proto;
	out->listener_l4proto = ctx->listener_l4proto;
	get_tuples(skb, &out->tuples, &ctx->iph, &ctx->ipv6h, &ctx->tcph, &ctx->udph, ctx->l4proto);
	return ret;
}

struct wan_egress_parsed {
	struct ethhdr ethh;
	struct tuples tuples;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 l4proto;
	__u8 listener_l4proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct wan_egress_parsed);
	__uint(max_entries, 1);
} wan_egress_scratch_map SEC(".maps");

static __always_inline int
parse_wan_egress_packet(struct __sk_buff *skb, u32 link_h_len,
			struct wan_egress_parsed *out)
{
	__u32 scratch_key = 0;
	struct parse_transport_ctx *ctx =
		bpf_map_lookup_elem(&parse_ctx_scratch_map, &scratch_key);

	if (!ctx)
		return -EFAULT;

	int ret = parse_transport(skb, link_h_len, ctx);

	// Fatal error: drop immediately, no context to copy.
	if (ret < 0)
		return ret;
	if (ctx->l4proto == IPPROTO_ICMPV6)
		return 1;

	// Always populate out with whatever IP context was parsed so PARSE_FRAGMENT
	// still preserves the source/destination tuple for callers and diagnostics.
	__builtin_memset(out, 0, sizeof(*out));
	out->ethh = ctx->ethh;
	out->tcph = ctx->tcph;
	out->udph = ctx->udph;
	out->l4proto = ctx->l4proto;
	out->listener_l4proto = ctx->listener_l4proto;
	get_tuples(skb, &out->tuples, &ctx->iph, &ctx->ipv6h, &ctx->tcph, &ctx->udph, ctx->l4proto);
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
	bool domain_word_cached;
	volatile __u8 route_state;
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

// Conntrack argument passing: per-CPU scratch for mark_*_seen wrappers.
// This avoids exceeding the BPF subprogram 5-argument limit while keeping the
// public mark_*_seen() signatures unchanged for all callers. The wrapper does a
// single PERCPU_ARRAY lookup, populates the scratch, and then threads the map
// value pointer into the noinline core to avoid a second helper call on the hot
// path. Older kernels may be stricter about BPF-to-BPF pointer propagation, so
// BPF tests should be kept enabled when touching this boundary.
#define CT_ARGS_HAS_ROUTING  BIT(0)
#define CT_ARGS_HAS_MAC      BIT(1)
#define CT_ARGS_HAS_PNAME    BIT(2)

struct conntrack_args {
	__u8 flags;        // CT_ARGS_HAS_* bitmask
	__u8 outbound;
	__u8 must;
	__u8 dscp;
	__u32 mark;
	__u32 pid;
	__u8 mac[6];
	__u8 padding[2];
	__u8 pname[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct conntrack_args);
	__uint(max_entries, 1);
} conntrack_args_map SEC(".maps");

// conntrack_args_set fully overwrites the per-CPU scratch so omitted optional
// fields never leak stale data from a previous packet processed on the same
// CPU. When called with compile-time NULL pointers the compiler can still
// dead-code-eliminate the corresponding branches.
static __always_inline void
conntrack_args_set(struct conntrack_args *a,
		   __u8 *outbound, __u32 *mark, __u8 *must, __u8 *mac,
		   __u8 dscp, const char *pname, __u32 pid)
{
	__u8 flags = 0;

	a->outbound = 0;
	a->must = 0;
	a->dscp = dscp;
	a->mark = 0;
	a->pid = 0;
	__builtin_memset(a->mac, 0, sizeof(a->mac));
	__builtin_memset(a->pname, 0, sizeof(a->pname));

	if (outbound) {
		flags |= CT_ARGS_HAS_ROUTING;
		a->outbound = *outbound;
		a->mark = *mark;
		a->must = *must;
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

static __always_inline const char *
conntrack_args_pname_or_null(const struct conntrack_args *a)
{
	return a->flags & CT_ARGS_HAS_PNAME ? (const char *)a->pname : NULL;
}

/*
 * Helper functions to simplify route_loop_cb switch-case.
 * These inline functions reduce code duplication and improve maintainability.
 */

// Check if a port falls within a range [port_start, port_end]
static __always_inline bool check_port_range(__u16 port, __u16 port_start, __u16 port_end)
{
	return port_start <= port && port <= port_end;
}

// Check if any bits in value match the mask (bitwise AND)
static __always_inline bool check_bitmask(__u8 value, __u8 mask)
{
	return (value & mask) != 0;
}

static __always_inline bool route_state_has(const struct route_ctx *ctx,
					    __u8 flags)
{
	return (ctx->route_state & flags) != 0;
}

static __always_inline void route_state_set(struct route_ctx *ctx, __u8 flags)
{
	ctx->route_state |= flags;
}

static __always_inline void route_state_clear(struct route_ctx *ctx, __u8 flags)
{
	ctx->route_state &= ~flags;
}

// Mark the current match_set as matched
static __always_inline void mark_matched(struct route_ctx *ctx)
{
	route_state_set(ctx, ROUTE_STATE_GOOD_SUBRULE);
}

static __always_inline int
route_match_lpm(struct route_ctx *ctx, const struct match_set *match_set,
		struct lpm_key *lpm_key)
{
	struct map_lpm_type *lpm;

	lpm = bpf_map_lookup_elem(&lpm_array_map, &match_set->index);
	if (unlikely(!lpm)) {
		ctx->result = -EFAULT;
		return 1;
	}

	if (bpf_map_lookup_elem(lpm, lpm_key)) {
		// match_set hits.
		mark_matched(ctx);
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
	__u32 bitmap_word_idx = index / 32;
	struct domain_routing *domain_routing;

	if (unlikely(bitmap_word_idx >= MAX_MATCH_SET_LEN / 32)) {
		ctx->result = -EFAULT;
		return 1;
	}

	if (!ctx->domain_word_cached || ctx->domain_word_idx != bitmap_word_idx) {
		// Refresh one 32-rule bitmap word at a time.
		__be32 daddr[4];

		__builtin_memcpy(daddr, ctx->lpm_key_daddr.data, sizeof(daddr));
		domain_routing = bpf_map_lookup_elem(&domain_routing_map, daddr);
		ctx->domain_word_idx = bitmap_word_idx;
		if (domain_routing)
			ctx->domain_word_bits =
				domain_routing->bitmap[bitmap_word_idx];
		else
			ctx->domain_word_bits = 0;
		ctx->domain_word_cached = true;
	}

	if ((ctx->domain_word_bits >> (index % 32)) & 1)
		mark_matched(ctx);
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
		if (check_port_range(check_port, match_set->port_range.port_start,
				     match_set->port_range.port_end))
			mark_matched(ctx);
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
		if (check_bitmask(value, mask))
			mark_matched(ctx);
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
			mark_matched(ctx);
		break;
	case MatchType_Dscp:
#ifdef __DEBUG_ROUTING
		bpf_printk(
			"CHECK: dscp, match_set->type: %u, not: %d, outbound: %u",
			match_type, match_set->not, match_set->outbound);
#endif
		if (dscp == match_set->dscp)
			mark_matched(ctx);
		break;
	case MatchType_Fallback:
#ifdef __DEBUG_ROUTING
		bpf_printk("CHECK: hit fallback");
#endif
		mark_matched(ctx);
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
		   route_state_has(ctx, ROUTE_STATE_GOOD_SUBRULE),
		   route_state_has(ctx, ROUTE_STATE_BAD_RULE));
#endif
	if (match_outbound != OUTBOUND_LOGICAL_OR) {
		// This match_set reaches the end of subrule.
		// We are now at end of rule, or next match_set belongs to another
		// subrule.
		if (route_state_has(ctx, ROUTE_STATE_GOOD_SUBRULE) == match_not)
			// This subrule does not hit.
			route_state_set(ctx, ROUTE_STATE_BAD_RULE);

		// Reset good_subrule.
		route_state_clear(ctx, ROUTE_STATE_GOOD_SUBRULE);
	}
#ifdef __DEBUG_ROUTING
	bpf_printk("_bad_rule: %d", route_state_has(ctx, ROUTE_STATE_BAD_RULE));
#endif
	if ((match_outbound & OUTBOUND_LOGICAL_MASK) != OUTBOUND_LOGICAL_MASK) {
		// Tail of a rule (line).
		// Decide whether to hit.
		if (!route_state_has(ctx, ROUTE_STATE_BAD_RULE)) {
#ifdef __DEBUG_ROUTING
			bpf_printk(
				"MATCHED: match_set->type: %u, match_set->not: %d",
				match_set->type, match_not);
#endif
			// DNS requests should routed by control plane if outbound is not
			// must_direct.
			if (unlikely(match_outbound == OUTBOUND_MUST_RULES)) {
				route_state_set(ctx, ROUTE_STATE_MUST);
			} else {
				bool must = route_state_has(ctx, ROUTE_STATE_MUST) ||
					    match_set->must;

				if (!must &&
				    route_state_has(ctx, ROUTE_STATE_DNS_QUERY)) {
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
		route_state_clear(ctx, ROUTE_STATE_BAD_RULE);
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

	// Rule is like: domain(suffix:baidu.com, suffix:google.com) && port(443) ->
	// proxy Subrule is like: domain(suffix:baidu.com, suffix:google.com) Match
	// set is like: suffix:baidu.com
	if (unlikely(index >= MAX_MATCH_SET_LEN)) {
		ctx->result = -EFAULT;
		return 1;
	}

	__u32 k = index; // Clone to pass code checker.

	match_set = bpf_map_lookup_elem(&routing_map, &k);
	if (unlikely(!match_set)) {
		ctx->result = -EFAULT;
		return 1;
	}

	if (!route_state_has(
		    ctx, ROUTE_STATE_BAD_RULE | ROUTE_STATE_GOOD_SUBRULE)) {
		if (route_eval_match(ctx, match_set, k, l4proto_type,
				     ipversion_type, pname, is_wan, dscp))
			return 1;
	} else {
#ifdef __DEBUG_ROUTING
		bpf_printk("key(match_set->type): %llu", match_set->type);
		bpf_printk("Skip to judge. bad_rule: %d, good_subrule: %d",
			   route_state_has(ctx, ROUTE_STATE_GOOD_SUBRULE),
			   route_state_has(ctx, ROUTE_STATE_BAD_RULE));
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

	__u32 active_rules_len = MAX_MATCH_SET_LEN;
	__u32 *active_rules_len_ptr =
		bpf_map_lookup_elem(&routing_meta_map, &zero_key);
	int ret;

	if (active_rules_len_ptr && *active_rules_len_ptr <= MAX_MATCH_SET_LEN)
		active_rules_len = *active_rules_len_ptr;

	struct route_loop_ctx loop_ctx = {
		.work = ctx,
	};
	ret = bpf_loop(active_rules_len, route_loop_cb, &loop_ctx, 0);
	if (unlikely(ret < 0))
		return ret;
	if (ctx->result >= 0)
		return ctx->result;
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

static __always_inline int redirect_to_control_plane_ingress(void)
{
	// bpf_redirect_peer() is only safe when explicitly enabled by userspace after
	// verifying: netkit+scrub=NONE + kernel >= 6.8 (CVE-2025-37959 fix).
	// Provides ~50% throughput improvement by bypassing CPU backlog.
	if (PARAM.use_redirect_peer)
		return bpf_redirect_peer(PARAM.dae0_ifindex, 0);
	return bpf_redirect(PARAM.dae0_ifindex, 0);
}

static __always_inline int redirect_to_control_plane_egress(void)
{
	// bpf_redirect_peer() is NOT supported in egress direction.
	// Only use it for ingress hooks.
	return bpf_redirect(PARAM.dae0_ifindex, 0);
}

static __noinline int prep_redirect_to_control_plane(
	struct __sk_buff *skb, __u32 link_h_len, struct tuples *tuples,
	struct ethhdr *ethh, __u8 from_wan)
{
	struct redirect_tuple redirect_tuple = {};
	struct redirect_entry redirect_entry = {};
	__u32 local_link_h_len = link_h_len;
	struct ethhdr *local_ethh = ethh;
	__u8 local_from_wan = from_wan;
	bool use_redirect_peer = PARAM.use_redirect_peer && !local_from_wan;

	if (!use_redirect_peer) {
		if (!local_link_h_len) {
			__u16 l3proto = skb->protocol;
			__u8 zero_mac[6] = {0};
			int ret;

			ret = bpf_skb_change_head(skb, sizeof(struct ethhdr), 0);
			if (ret) {
				bpf_printk("prep_redirect: bpf_skb_change_head failed: %d", ret);
				return ret;
			}
			bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
					    &l3proto, sizeof(l3proto), 0);
			bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
					    zero_mac, sizeof(zero_mac), 0);
		}

		bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
				    (void *)&PARAM.dae0peer_mac, 6, 0);
	}

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		redirect_tuple.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple.sip.u6_addr32[3] = tuples->five.sip.u6_addr32[3];
		redirect_tuple.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple.dip.u6_addr32[3] = tuples->five.dip.u6_addr32[3];
	} else {
		__builtin_memcpy(&redirect_tuple.sip, &tuples->five.sip, IPV6_BYTE_LENGTH);
		__builtin_memcpy(&redirect_tuple.dip, &tuples->five.dip, IPV6_BYTE_LENGTH);
	}

	redirect_entry.ifindex = skb->ifindex;
	redirect_entry.from_wan = local_from_wan;
	redirect_entry.last_seen_ns = bpf_ktime_get_ns();
	if (local_link_h_len == ETH_HLEN) {
		__builtin_memcpy(redirect_entry.smac, local_ethh->h_source, 6);
		__builtin_memcpy(redirect_entry.dmac, local_ethh->h_dest, 6);
	} else {
		__builtin_memset(redirect_entry.smac, 0, 6);
		__builtin_memset(redirect_entry.dmac, 0, 6);
	}
	bpf_map_update_elem(&redirect_track, &redirect_tuple, &redirect_entry, BPF_ANY);

	return 0;
}

// copy_reversed_tuples moved below, timer callback removed (using userspace janitor)

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

// DNS queries/replies are short-lived; skipping conntrack/cache for them
// reduces unnecessary UDP state churn.
static __always_inline bool is_short_lived_udp_traffic(struct tuples_key *key)
{
	return key->l4proto == IPPROTO_UDP &&
	       (key->dport == bpf_htons(53) || key->sport == bpf_htons(53));
}

// mark_udp_seen updates the last_seen_ns timestamp for UDP connection tracking.
// Uses datapath lazy expiry with userspace janitor as a backstop under pressure.
//
// Design choice: Kernel path deletes clearly expired entries on lookup so stale
// state stops affecting routing without waiting for the next userspace sweep.
// Userspace still performs periodic cleanup to recover space from cold entries
// that are never touched again.
//
// Scheme3: Routing is embedded in conn state for single source of truth.
// When routing params are provided (outbound != NULL), they're stored in conn state.
//
// Robustness: If map is full (E2BIG), we increment overflow counter and return NULL.
// Callers should gracefully degrade: continue processing without conntrack state
// rather than dropping packets.
//
// Performance: The heavy body (__mark_udp_seen) is __noinline so it is emitted
// once in the BPF object instead of being duplicated at every call-site.
// Routing args are passed via conntrack_args_map (PERCPU_ARRAY, ~0 cost).
#define UDP_CONN_STATE_TIMEOUT_NS 120000000000ULL        // 120-second backstop; userspace endpoint teardown is the primary owner
#define UDP_CONN_STATE_UPDATE_INTERVAL_NS 1000000000ULL  // 1 second

static __always_inline bool
udp_conn_state_expired(const struct udp_conn_state *state, __u64 now)
{
	return state && now - state->last_seen_ns > UDP_CONN_STATE_TIMEOUT_NS;
}

static __noinline struct udp_conn_state *
__mark_udp_seen(struct tuples_key *key, bool is_wan_ingress_direction,
		const struct conntrack_args *args)
{
	if (!args)
		return NULL;

	__u64 now = bpf_ktime_get_ns();
	struct udp_conn_state *state =
		bpf_map_lookup_elem(&udp_conn_state_map, key);

	if (udp_conn_state_expired(state, now)) {
		bpf_map_delete_elem(&udp_conn_state_map, key);
		state = NULL;
	}

	if (state) {
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
			publish_routing_meta(&state->meta, meta);
		}
		return state;
	}

	// Slow path: create new entry (either no entry or expired one was deleted)
	bool has_rt = !!(args->flags & CT_ARGS_HAS_ROUTING);
	struct udp_conn_state new_state = {};

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
	}

	int ret = bpf_map_update_elem(&udp_conn_state_map, key,
				      &new_state, BPF_ANY);

	if (unlikely(ret)) {
		// Map full or other error: increment overflow counter
		__u32 stats_key = BPF_STATS_UDP_CONN_OVERFLOW;
		__u64 *overflow_count =
			bpf_map_lookup_elem(&bpf_stats_map, &stats_key);

		if (overflow_count)
			__sync_fetch_and_add(overflow_count, 1);
		send_dae_event(DAE_EVENT_UDP_CONN_OVERFLOW, args->pid,
			       conntrack_args_pname_or_null(args), 0,
			       key->l4proto, key->sip.u6_addr32,
			       key->dip.u6_addr32, key->sport, key->dport);
		return NULL;
	}

	return bpf_map_lookup_elem(&udp_conn_state_map, key);
}

// mark_udp_seen: thin inline wrapper that populates per-CPU scratch args once
// and then delegates to the single-copy __mark_udp_seen body.
static __always_inline struct udp_conn_state *
mark_udp_seen(struct tuples_key *key, bool is_wan_ingress_direction,
	      __u8 *outbound, __u32 *mark, __u8 *must, __u8 *mac,
	      __u8 dscp, const char *pname, __u32 pid)
{
	__u32 zero = 0;
	struct conntrack_args *args =
		bpf_map_lookup_elem(&conntrack_args_map, &zero);

	if (unlikely(!args))
		return NULL;
	conntrack_args_set(args, outbound, mark, must, mac, dscp, pname, pid);
	return __mark_udp_seen(key, is_wan_ingress_direction, args);
}

// mark_tcp_seen updates TCP connection state for lifecycle tracking.
// Uses datapath lazy expiry with userspace janitor as a backstop under pressure.
//
// Design choice: Kernel path deletes clearly expired entries on lookup so stale
// state stops affecting routing without waiting for the next userspace sweep.
// Userspace still performs periodic cleanup to recover space from cold entries
// that are never touched again.
//
// State transitions:
// - SYN -> TCP_STATE_ACTIVE
// - FIN/RST -> TCP_STATE_CLOSING
//
// Scheme3: Routing is embedded in conn state for single source of truth.
// When routing params are provided (outbound != NULL), they're stored in
// conn state. Only SYN path should provide routing params.
//
// Returns state pointer on success, or NULL if allocation failed or a non-SYN
// packet has no cached state (caller should preserve passthrough behavior).
// Performance: The heavy body (__mark_tcp_seen) is __noinline so it is emitted
// once in the BPF object instead of being duplicated at every call-site.
#define TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS 120000000000ULL  // 120 seconds
#define TCP_CONN_STATE_CLOSING_TIMEOUT_NS 10000000000ULL       // 10 seconds
#define TCP_CONN_STATE_UPDATE_INTERVAL_NS 1000000000ULL  // 1 second

static __always_inline bool
tcp_conn_state_expired(const struct tcp_conn_state *state, __u64 now)
{
	__u64 timeout = TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS;

	if (!state)
		return false;
	if (state->state == TCP_STATE_CLOSING)
		timeout = TCP_CONN_STATE_CLOSING_TIMEOUT_NS;
	return now - state->last_seen_ns > timeout;
}

// __mark_tcp_seen: noinline core. tcp_flags: bit 0 = SYN && !ACK (new
// connection), bit 1 = FIN || RST.
static __noinline struct tcp_conn_state *
__mark_tcp_seen(struct tuples_key *key, bool is_wan_ingress_direction,
		__u8 tcp_flags, const struct conntrack_args *args)
{
	if (!args)
		return NULL;

	__u64 now = bpf_ktime_get_ns();
	struct tcp_conn_state *state =
		bpf_map_lookup_elem(&tcp_conn_state_map, key);
	bool new_conn_syn = tcp_flags & 1;
	bool is_fin_rst   = tcp_flags & 2;

	/*
	 * A pure SYN always starts a fresh TCP lifecycle. If an older entry still
	 * exists under the same 4-tuple (for example because only the reverse-side
	 * FIN/RST was observed previously), drop it now so the new connection does
	 * not inherit stale routing metadata.
	 */
	if (state && new_conn_syn) {
		bpf_map_delete_elem(&tcp_conn_state_map, key);
		state = NULL;
	} else if (tcp_conn_state_expired(state, now)) {
		bpf_map_delete_elem(&tcp_conn_state_map, key);
		state = NULL;
	}

	if (state) {
		// Fast path: lazy timestamp update (only if interval > 1 second)
		if (now - state->last_seen_ns > TCP_CONN_STATE_UPDATE_INTERVAL_NS)
			state->last_seen_ns = now;

		// Check for connection close signals (FIN or RST)
		if (is_fin_rst)
			state->state = TCP_STATE_CLOSING;

		// Update routing if provided (rare: routing decision changed)
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
			publish_routing_meta(&state->meta, meta);
		}

		return state;
	}

	// Only create new entry on SYN (new connection)
	if (new_conn_syn) {
		bool has_rt = !!(args->flags & CT_ARGS_HAS_ROUTING);
		struct tcp_conn_state new_state = {};

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
		}

		int ret = bpf_map_update_elem(&tcp_conn_state_map, key,
					      &new_state, BPF_ANY);

		if (unlikely(ret)) {
			__u32 stats_key = BPF_STATS_TCP_CONN_OVERFLOW;
			__u64 *overflow_count =
				bpf_map_lookup_elem(&bpf_stats_map, &stats_key);

			if (overflow_count)
				__sync_fetch_and_add(overflow_count, 1);
			send_dae_event(DAE_EVENT_TCP_CONN_OVERFLOW, args->pid,
				       conntrack_args_pname_or_null(args), 0,
				       key->l4proto, key->sip.u6_addr32,
				       key->dip.u6_addr32, key->sport,
				       key->dport);
			return NULL;
		}

		return bpf_map_lookup_elem(&tcp_conn_state_map, key);
	}

	// Non-SYN packets without existing state must never allocate new state.
	return NULL;
}

// mark_tcp_seen: thin inline wrapper that populates per-CPU scratch args once
// and then delegates to the single-copy __mark_tcp_seen body.
static __always_inline struct tcp_conn_state *
mark_tcp_seen(struct tuples_key *key, const struct tcphdr *tcph,
	      bool is_wan_ingress_direction,
	      __u8 *outbound, __u32 *mark, __u8 *must, __u8 *mac,
	      __u8 dscp, const char *pname, __u32 pid)
{
	__u32 zero = 0;
	struct conntrack_args *args =
		bpf_map_lookup_elem(&conntrack_args_map, &zero);

	if (unlikely(!args))
		return NULL;
	conntrack_args_set(args, outbound, mark, must, mac, dscp, pname, pid);

	__u8 tcp_flags = 0;

	if (tcph->syn && !tcph->ack)
		tcp_flags |= 1;
	if (tcph->fin || tcph->rst)
		tcp_flags |= 2;
	return __mark_tcp_seen(key, is_wan_ingress_direction, tcp_flags, args);
}

static __always_inline bool is_new_tcp_connection(const struct tcphdr *tcph)
{
	return tcph->syn && !tcph->ack;
}

// Unified non-syn TCP handling entry for WAN egress.
// Scheme3: Load routing from embedded conn state.
// Keep main-equivalent behavior:
// - Reuse cached routing result for established connections.
// - If no cache, do not affect pre-existing/server-side flows.
static __noinline int do_tproxy_lan_egress(struct __sk_buff *skb, u32 link_h_len)
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
		return TC_ACT_OK;
	}

	if (skb->ingress_ifindex == NOWHERE_IFINDEX &&  // Only drop NDP_REDIRECT packets from localhost
		ctx->l4proto == IPPROTO_ICMPV6 && ctx->icmp6h.icmp6_type == NDP_REDIRECT) {
		// REDIRECT (NDP)
		return TC_ACT_SHOT;
	}

	// Update UDP Conntrack
	if (ctx->l4proto == IPPROTO_TCP) {
		struct tuples tuples;
		struct tuples_key reversed_tuples_key;

		get_tuples(skb, &tuples, &ctx->iph, &ctx->ipv6h,
			   &ctx->tcph, &ctx->udph, ctx->l4proto);
		copy_reversed_tuples(&tuples.five, &reversed_tuples_key);
		// Reverse-side TCP packets should refresh the forward conn-state and
		// surface FIN/RST so the lifecycle does not remain ACTIVE until the
		// janitor backstop expires.
		mark_tcp_seen(&reversed_tuples_key, &ctx->tcph, true,
			      NULL, NULL, NULL, NULL,
			      0, NULL, 0);
	} else if (ctx->l4proto == IPPROTO_UDP) {
		// DNS traffic is short-lived and stateless in our fast path.
		// Skip tuple build + conntrack update to reduce state churn.
		if (ctx->udph.source == bpf_htons(53) || ctx->udph.dest == bpf_htons(53))
			return TC_ACT_PIPE;

		struct tuples tuples;
		struct tuples_key reversed_tuples_key;

		get_tuples(skb, &tuples, &ctx->iph, &ctx->ipv6h,
			   &ctx->tcph, &ctx->udph, ctx->l4proto);
		copy_reversed_tuples(&tuples.five, &reversed_tuples_key);
		// Robustness: If conntrack map is full, gracefully degrade by continuing
		// without state tracking. This is acceptable as the packet will be processed
		// normally; we just lose connection tracking optimization.
		mark_udp_seen(&reversed_tuples_key, true,
			      NULL, NULL, NULL, NULL,
			      0, NULL, 0);
	}

	return TC_ACT_PIPE;
}

SEC("tc/lan_egress_l2")
int tproxy_lan_egress_l2(struct __sk_buff *skb)
{
	return do_tproxy_lan_egress(skb, 14);
}

SEC("tc/lan_egress_l3")
int tproxy_lan_egress_l3(struct __sk_buff *skb)
{
	return do_tproxy_lan_egress(skb, 0);
}

static __noinline bool
wan_outbound_is_alive(struct __sk_buff *skb, __u8 outbound, __u8 l4proto,
		      __be16 dport);

static __noinline int
redirect_lan_packet_to_control_plane(struct __sk_buff *skb, __u32 link_h_len,
				     struct lan_ingress_parsed *pkt,
				     __u64 routing_meta_raw)
{
	union routing_meta routing_meta = {
		.raw = routing_meta_raw,
	};
	struct routing_handoff_entry handoff = {};

	if (prep_redirect_to_control_plane(skb, link_h_len, &pkt->tuples,
					   &pkt->ethh, 0)) {
		// Failed to prepare packet (e.g., bpf_skb_change_head failed under memory pressure)
		// Fall back to direct pass to avoid packet corruption
		return TC_ACT_OK;
	}

	skb->cb[0] = TPROXY_MARK;
	skb->cb[1] = pkt->listener_l4proto;

	handoff.last_seen_ns = bpf_ktime_get_ns();
	handoff.result.mark = routing_meta.data.mark;
	handoff.result.must = routing_meta.data.must;
	handoff.result.outbound = routing_meta.data.outbound;
	handoff.result.dscp = routing_meta.data.dscp;
	__builtin_memcpy(handoff.result.mac, pkt->ethh.h_source, 6);
	bpf_map_update_elem(&routing_handoff_map, &pkt->tuples.five,
			    &handoff, BPF_ANY);
	return redirect_to_control_plane_ingress();
}

static __noinline int do_tproxy_lan_ingress(struct __sk_buff *skb, u32 link_h_len)
{
	// Use per-CPU scratch map to avoid stack overflow (512-byte limit).
	// The call chain lan_ingress -> parse_lan_ingress_packet -> parse_transport
	// would otherwise exceed the stack limit.
	__u32 scratch_key = 0;
	struct lan_ingress_parsed *pkt =
		bpf_map_lookup_elem(&lan_ingress_scratch_map, &scratch_key);

	if (!pkt)
		return TC_ACT_SHOT;

	/* Ensure scratch bytes are initialized even if verifier can't precisely
	 * track writes done through callee pointer arguments. */
	__builtin_memset(pkt, 0, sizeof(*pkt));
	int ret = parse_lan_ingress_packet(skb, link_h_len, pkt);

	if (ret) {
		// Negative return: parsing error (malformed packet, too many extension headers, etc.)
		// Positive return: unsupported protocol or non-initial fragment - pass through
		if (ret < 0) {
			bpf_printk("parse_transport error: %d, dropping", ret);
			return TC_ACT_SHOT;  // Drop malformed/suspicious packets
		}
		return TC_ACT_OK;  // Pass through unsupported protocols
	}

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
		struct tcp_conn_state *tcp_state;

		// Track TCP connection state (update timestamp, detect FIN/RST).
		// PERFORMANCE: Use the returned conn_state pointer to avoid a second map lookup.
		tcp_state = mark_tcp_seen(&pkt->tuples.five, &pkt->tcph, false,
					  NULL, NULL, NULL, NULL,
					  0, NULL, 0);
		// No cached state for an established packet: keep the historical
		// passthrough behavior instead of recomputing routing.
		if (!tcp_state)
			return TC_ACT_OK;

		/*
		 * Compatibility restore for 030902f behavior and align with WAN
		 * non-SYN session handling: reuse cached routing result for
		 * established TCP packets.
		 * Scheme3: Load routing directly from the conn_state we already looked up.
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
		if (!wan_outbound_is_alive(skb, outbound, pkt->l4proto,
					   pkt->tuples.five.dport))
			return TC_ACT_SHOT;
		return redirect_lan_packet_to_control_plane(
			skb, link_h_len, pkt, tcp_state->meta.raw);
	}

	// Routing for new connection.
	__u32 route_flag[8] = {};
	struct tcp_conn_state *tcp_state = NULL;
	struct udp_conn_state *udp_state = NULL;

	if (pkt->l4proto == IPPROTO_TCP) {
		// Track TCP connection state for new connections from LAN.
		// This ensures routing cache entries can be cleaned up via
		// cascade deletion when the connection expires.
		tcp_state = mark_tcp_seen(&pkt->tuples.five, &pkt->tcph, false,
					  NULL, NULL, NULL, NULL,
					  pkt->tuples.dscp, NULL, 0);
		route_flag[0] = L4ProtoType_TCP;
	} else {
		if (!is_short_lived_udp_traffic(&pkt->tuples.five)) {
			// Fast path: Check conn state for established UDP flows
			udp_state = mark_udp_seen(&pkt->tuples.five, false,
						  NULL, NULL, NULL, NULL,
						  pkt->tuples.dscp, NULL, 0);
			// Robustness: If conntrack map is full (conn_state == NULL),
			// gracefully degrade by continuing with normal routing instead of
			// dropping the packet. We lose the "direct return path" optimization
			// for reply packets, but service continues.
			if (udp_state && udp_state->is_wan_ingress_direction) {
				// Replay (outbound) of an inbound flow => direct.
				return TC_ACT_OK;
			}

			// Fast path: Use cached routing if available
			if (udp_state && udp_state->meta.data.has_routing) {
				// Load routing from conn state - skip expensive route() call!
				__u8 outbound = udp_state->meta.data.outbound;
				__u32 mark = udp_state->meta.data.mark;

				if (outbound == OUTBOUND_DIRECT) {
					skb->mark = mark;
					goto direct;
				} else if (unlikely(outbound == OUTBOUND_BLOCK)) {
					goto block;
				}

				if (!wan_outbound_is_alive(skb, outbound, pkt->l4proto,
							   pkt->tuples.five.dport))
					goto block;

				// Update conn state timestamp for this fast path packet
				udp_state->last_seen_ns = bpf_ktime_get_ns();
				return redirect_lan_packet_to_control_plane(
					skb, link_h_len, pkt, udp_state->meta.raw);
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

	// Socket lookup BEFORE routing to detect local services (NAT loopback).
	// This must happen before route() because routing rules might incorrectly
	// send local-service traffic to a proxy.
	//
	// For TCP: Only LISTEN sockets indicate local services.
	// For UDP: Any matching socket indicates a local service (UDP has no LISTEN state).
	// Note: UDP socket lookup is safe here because dae's own outbound UDP sockets
	// have completely different tuples (different source/dest IP:port combinations),
	// so they won't match the NAT loopback packet tuple.
	//
	// IMPORTANT: For TCP, skip socket lookup on SYN packets. This is critical for
	// compatibility with CF back-to-source and NAT loopback scenarios. Performing
	// socket lookup on SYN packets can interfere with legitimate new connections
	// to local services that should be routed through dae.
	if (pkt->l4proto == IPPROTO_TCP || pkt->l4proto == IPPROTO_UDP) {
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

		if (pkt->l4proto == IPPROTO_TCP) {
			// Perform socket lookup ONLY for established TCP connections.
			// Skip socket lookup for SYN packets (new connections).
			// This ensures compatibility with CF back-to-source and NAT
			// loopback scenarios where new connections to local services
			// should be routed through dae first.
			if (!(pkt->tcph.syn && !pkt->tcph.ack)) {
				// Established TCP connection - perform socket lookup
				sk = bpf_skc_lookup_tcp(skb, &tuple, tuple_size,
							PARAM.dae_netns_id, 0);
				if (sk) {
					if (!bpf_sock_is_dae_socket(sk) &&
					    sk->state == BPF_TCP_LISTEN) {
						// Found LISTEN socket - local service (NAT loopback).
						// Pass through to kernel stack directly, bypassing dae.
						bpf_sk_release(sk);
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
						bpf_printk("tcp(lan): local LISTEN socket found, pass through");
#endif
						return TC_ACT_OK;
					}
					// Not a LISTEN socket - established connection or dae's own socket.
					// Continue with routing to determine how to handle this packet.
					bpf_sk_release(sk);
				}
			}
			// For SYN packets (new connections), skip socket lookup and continue to routing
		} else {
			// UDP: Any non-dae socket matching the destination tuple is a local service.
			sk = bpf_sk_lookup_udp(skb, &tuple, tuple_size,
					       PARAM.dae_netns_id, 0);
			if (sk) {
				if (!bpf_sock_is_dae_socket(sk)) {
					bpf_sk_release(sk);
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
					bpf_printk("udp(lan): local socket found, pass through");
#endif
					return TC_ACT_OK;
				}
				bpf_sk_release(sk);
			}
		}
		// No socket found - continue to routing
	}
	// For UDP replies to WAN ingress traffic, we also use is_wan_ingress_direction
	// flag in conn_state (set in wan_ingress path) as a secondary detection method.

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

	// Scheme3: Embed routing in conn state for single source of truth.
	// Update conn state with routing decision (skip DNS for optimization).
	// PERFORMANCE: Use the conn_state pointer from first call to avoid
	// a second map lookup. This is critical for high-throughput traffic.
	if (pkt->l4proto == IPPROTO_UDP &&
	    is_short_lived_udp_traffic(&pkt->tuples.five)) {
		// Skip cache for short-lived DNS to avoid map churn.
	} else if (pkt->l4proto == IPPROTO_TCP && tcp_state) {
		// Directly update the TCP conn state we already looked up
		__builtin_memcpy(tcp_state->mac, pkt->ethh.h_source, 6);
		union routing_meta _m = build_routing_meta(outbound, mark, must,
							    pkt->tuples.dscp);
		publish_routing_meta(&tcp_state->meta, _m);
	} else if (pkt->l4proto == IPPROTO_UDP && udp_state) {
		// Directly update the UDP conn state we already looked up
		__builtin_memcpy(udp_state->mac, pkt->ethh.h_source, 6);
		union routing_meta _m = build_routing_meta(outbound, mark, must,
							    pkt->tuples.dscp);
		publish_routing_meta(&udp_state->meta, _m);
	}

	// SECURITY: Fail-Closed for TCP connections requiring proxy when conn state map is full.
	// If we couldn't store conn state for a TCP packet that needs proxying,
	// we MUST drop it to prevent traffic leakage on subsequent packets.
	if (pkt->l4proto == IPPROTO_TCP && !tcp_state) {
		if (outbound == OUTBOUND_DIRECT && mark == 0) {
			// Direct connection with default routing - no state needed
			skb->mark = mark;
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
			bpf_printk("tcp(lan): GO OUTBOUND_DIRECT (MAP FULL)");
#endif
			goto direct;
		}
		// Either proxied connection, or direct connection with policy routing mark.
		// State is REQUIRED. Without state, subsequent packets won't have the
		// mark applied (direct) or will bypass proxy (proxied), causing either
		// asymmetric routing failure or traffic leakage.
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

	// Handle routing result: DIRECT, BLOCK, or proxy
	if (outbound == OUTBOUND_DIRECT) {
		// Direct connection - pass through to kernel stack
		skb->mark = mark;
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("GO OUTBOUND DIRECT");
#endif
		goto direct;
	} else if (unlikely(outbound == OUTBOUND_BLOCK)) {
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("SHOT OUTBOUND_BLOCK");
#endif
		// Send DAE_EVENT_BLOCKED event
		send_dae_event(DAE_EVENT_BLOCKED, 0, NULL, outbound,
			       pkt->l4proto, pkt->tuples.five.sip.u6_addr32,
			       pkt->tuples.five.dip.u6_addr32,
			       pkt->tuples.five.sport, pkt->tuples.five.dport);
		goto block;
	}

	if (!wan_outbound_is_alive(skb, outbound, pkt->l4proto,
				   pkt->tuples.five.dport))
		goto block;
	return redirect_lan_packet_to_control_plane(
		skb, link_h_len, pkt,
		build_routing_meta(outbound, mark, must, pkt->tuples.dscp).raw);

direct:
	return TC_ACT_OK;

block:
	return TC_ACT_SHOT;
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

// Cookie will change after the first packet, so we just use it for
// handshake.
static __always_inline bool pid_is_control_plane(struct __sk_buff *skb,
						 struct pid_pname **p)
{
	struct pid_pname *pid_pname;
	__u64 cookie = bpf_get_socket_cookie(skb);

	pid_pname = bpf_map_lookup_elem(&cookie_pid_map, &cookie);
	if (pid_pname) {
		pid_pname->last_seen_ns = bpf_ktime_get_ns();
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
	if (PARAM.dae_socket_mark && skb->mark == PARAM.dae_socket_mark)
		return true;
	if ((skb->mark & 0x100) == 0x100)
		return true;
	return false;
}

static __noinline int do_tproxy_wan_ingress(struct __sk_buff *skb, u32 link_h_len)
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
		return TC_ACT_OK;
	}

	// Update reverse-direction conntrack state so server/local FIN/RST keeps
	// the original client-side lifecycle in sync.
	if (ctx->l4proto == IPPROTO_TCP) {
		struct tuples tuples;
		struct tuples_key reversed_tuples_key;

		get_tuples(skb, &tuples, &ctx->iph, &ctx->ipv6h,
			   &ctx->tcph, &ctx->udph, ctx->l4proto);
		copy_reversed_tuples(&tuples.five, &reversed_tuples_key);
		mark_tcp_seen(&reversed_tuples_key, &ctx->tcph, true,
			      NULL, NULL, NULL, NULL,
			      0, NULL, 0);
	} else if (ctx->l4proto == IPPROTO_UDP) {
		// DNS traffic is short-lived and stateless in our fast path.
		// Skip tuple build + conntrack update to reduce state churn.
		if (ctx->udph.source == bpf_htons(53) || ctx->udph.dest == bpf_htons(53))
			return TC_ACT_PIPE;

		struct tuples tuples;
		struct tuples_key reversed_tuples_key;

		get_tuples(skb, &tuples, &ctx->iph, &ctx->ipv6h,
			   &ctx->tcph, &ctx->udph, ctx->l4proto);
		copy_reversed_tuples(&tuples.five, &reversed_tuples_key);
		// Robustness: If conntrack map is full, gracefully degrade by continuing
		// without state tracking. This is acceptable as the packet will be processed
		// normally; we just lose connection tracking optimization.
		mark_udp_seen(&reversed_tuples_key, true,
			      NULL, NULL, NULL, NULL,
			      0, NULL, 0);
	}

	return TC_ACT_PIPE;
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

// Routing and redirect the packet back.
// We cannot modify the dest address here. So we cooperate with wan_ingress.
static __noinline bool
wan_outbound_is_alive(struct __sk_buff *skb, __u8 outbound, __u8 l4proto,
		      __be16 dport)
{
	/* DNS queries must always reach the control plane. User-space DNS
	 * routing is responsible for fallback, rejection and SERVFAIL
	 * synthesis; dropping UDP/53 here turns upstream health noise into
	 * client-visible timeouts.
	 */
	if (l4proto == IPPROTO_UDP && dport == bpf_htons(53))
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
do_tproxy_wan_egress_tcp(struct __sk_buff *skb, u32 link_h_len,
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
			return TC_ACT_OK;
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

		struct tcp_conn_state *tcp_conn = mark_tcp_seen(
			&tuples->five, tcph, false, outbound_ptr, mark_ptr,
			must_ptr, scratch->mac, dscp, pname_str, pid_val);

		if (!tcp_conn) {
			if (outbound == OUTBOUND_DIRECT && mark == 0)
				return TC_ACT_OK;
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
		// Established TCP connection (not SYN).
		// Fast-path optimization for WAN egress:
		// - Direct connections don't need state lookup (no state was saved for them)
		// - Proxied connections have cached routing that must be used
		//
		// To avoid unnecessary map lookups for direct traffic (the majority in many cases),
		// we don't call mark_tcp_seen here. Instead, we rely on a simple heuristic:
		// - Most direct connections are not cached (outbound==DIRECT, mark==0, !must)
		// - Proxied connections always have cached state
		//
		// Trade-off: Proxied connections will do a map lookup here. This is acceptable
		// because: (1) Proxy traffic is typically less frequent than direct traffic,
		// (2) Map lookup is required anyway to get the routing decision.
		//
		// Look up cached routing state (only for proxied connections).
		struct tcp_conn_state *tcp_conn = mark_tcp_seen(
			&tuples->five, tcph, false,
			NULL, NULL, NULL, NULL,
			0, NULL, 0);

		if (tcp_conn && tcp_conn->meta.data.has_routing) {
			// Proxied connection with cached routing.
			// Use cache to ensure all packets go through proxy.
			outbound = tcp_conn->meta.data.outbound;
			mark = tcp_conn->meta.data.mark;
			must = tcp_conn->meta.data.must;
			__builtin_memcpy(handoff_mac, tcp_conn->mac, 6);
			__builtin_memcpy(scratch->mac, tcp_conn->mac, 6);
			handoff_pname = (const char *)tcp_conn->pname;
			handoff_pid = tcp_conn->pid;
		} else {
			// No cached routing state.
			// This must be a direct connection (we don't save state for direct+mark==0)
			// or a pre-dae connection.
			// Fast-path: pass through without further processing.
			return TC_ACT_OK;
		}
	}

	if (outbound == OUTBOUND_DIRECT &&
	    mark == 0 // If mark is not zero, we should re-route it.
	) {
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("GO OUTBOUND_DIRECT");
#endif
		skb->mark = mark;
		return TC_ACT_OK;
	} else if (unlikely(outbound == OUTBOUND_BLOCK)) {
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("SHOT OUTBOUND_BLOCK");
#endif
		return TC_ACT_SHOT;
	}

	if (!wan_outbound_is_alive(skb, outbound, IPPROTO_TCP,
				   tuples->five.dport))
		return TC_ACT_SHOT;

	if (prep_redirect_to_control_plane(skb, link_h_len, tuples,
					   ethh, 1)) {
		// Failed to prepare packet (e.g., bpf_skb_change_head failed)
		// Fall back to direct pass to avoid packet corruption
		return TC_ACT_OK;
	}
	skb->cb[0] = TPROXY_MARK;
	skb->cb[1] = tcp_listener_l4proto(tcph);
	{
		struct routing_handoff_entry handoff = {};

		handoff.last_seen_ns = bpf_ktime_get_ns();
		handoff.result.mark = mark;
		handoff.result.must = must;
		handoff.result.outbound = outbound;
		handoff.result.pid = handoff_pid;
		handoff.result.dscp = tuples->dscp;
		__builtin_memcpy(handoff.result.mac, handoff_mac, 6);
		if (handoff_pname)
			__builtin_memcpy(handoff.result.pname, handoff_pname,
					 TASK_COMM_LEN);
		bpf_map_update_elem(&routing_handoff_map, &tuples->five,
				    &handoff, BPF_ANY);
	}
	return redirect_to_control_plane_egress();
}

static __noinline int
do_tproxy_wan_egress_udp(struct __sk_buff *skb, u32 link_h_len,
			 struct tuples *tuples, struct ethhdr *ethh,
			 struct udphdr *udph)
{
	struct pid_pname *pid_pname;
	__u8 outbound;
	__u32 mark;
	bool must;
	struct udp_conn_state *udp_conn_state = NULL;
	__u8 mac[6] = {};
	const char *handoff_pname = NULL;
	__u32 handoff_pid = 0;

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
		return TC_ACT_OK;

	if (!is_short_lived_udp_traffic(&tuples->five)) {
		udp_conn_state = mark_udp_seen(&tuples->five, false,
					       NULL, NULL, NULL, NULL,
					       0, NULL, 0);
		if (udp_conn_state && udp_conn_state->is_wan_ingress_direction)
			return TC_ACT_OK;

		if (udp_conn_state && udp_conn_state->meta.data.has_routing) {
			outbound = udp_conn_state->meta.data.outbound;
			mark = udp_conn_state->meta.data.mark;
			must = udp_conn_state->meta.data.must;
			__builtin_memcpy(mac, udp_conn_state->mac, 6);
			handoff_pname = (const char *)udp_conn_state->pname;
			handoff_pid = udp_conn_state->pid;
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

fast_path_skip_routing:
		if (udp_conn_state && tuples->five.dport != bpf_htons(53)) {
			if (outbound != OUTBOUND_DIRECT || mark != 0 || must) {
				__builtin_memcpy(udp_conn_state->mac, mac, 6);
				if (pid_pname) {
					__builtin_memcpy(udp_conn_state->pname,
							 pid_pname->pname,
							 TASK_COMM_LEN);
					udp_conn_state->pid = pid_pname->pid;
				}
				union routing_meta _m = build_routing_meta(outbound,
								   mark,
								   must,
								   tuples->dscp);
				publish_routing_meta(&udp_conn_state->meta, _m);
			}
		udp_conn_state->last_seen_ns = bpf_ktime_get_ns();
	}

#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
	__u32 pid = pid_pname ? pid_pname->pid : 0;

	bpf_printk("udp(wan): from %pI6:%u [PID %u]", tuples->five.sip.u6_addr32,
		   bpf_ntohs(tuples->five.sport), pid);
	bpf_printk("udp(wan): outbound: %u, %pI6:%u", outbound,
		   tuples->five.dip.u6_addr32, bpf_ntohs(tuples->five.dport));
#endif

	if (outbound == OUTBOUND_DIRECT && mark == 0)
		return TC_ACT_OK;
	else if (unlikely(outbound == OUTBOUND_BLOCK))
		return TC_ACT_SHOT;

	if (!wan_outbound_is_alive(skb, outbound, IPPROTO_UDP,
				   tuples->five.dport))
		return TC_ACT_SHOT;

	if (prep_redirect_to_control_plane(skb, link_h_len, tuples,
					   ethh, 1)) {
		return TC_ACT_OK;
	}
	skb->cb[0] = TPROXY_MARK;
	skb->cb[1] = IPPROTO_UDP;
	{
		struct routing_handoff_entry handoff = {};

		handoff.last_seen_ns = bpf_ktime_get_ns();
		handoff.result.mark = mark;
		handoff.result.must = must;
		handoff.result.outbound = outbound;
		handoff.result.pid = handoff_pid;
		handoff.result.dscp = tuples->dscp;
		__builtin_memcpy(handoff.result.mac, mac, 6);
		if (handoff_pname)
			__builtin_memcpy(handoff.result.pname, handoff_pname,
					 TASK_COMM_LEN);
		bpf_map_update_elem(&routing_handoff_map, &tuples->five,
				    &handoff, BPF_ANY);
	}
	return redirect_to_control_plane_egress();
}

/*
 * Keep wan_egress as a BPF subprogram to avoid verifier state explosion on
 * newer kernels (e.g. Debian 6.12), while preserving routing semantics.
 *
 * Note: We use per-CPU scratch map instead of stack allocation to avoid
 * exceeding the 512-byte stack limit. The call chain is:
 *   tproxy_wan_egress_* -> do_tproxy_wan_egress -> parse_wan_egress_packet -> parse_transport
 * which would otherwise use >512 bytes of combined stack.
 */
static __noinline int do_tproxy_wan_egress(struct __sk_buff *skb, u32 link_h_len)
{
	// Skip packets not from localhost.
	if (skb->ingress_ifindex != NOWHERE_IFINDEX)
		return TC_ACT_OK;

	// Use per-CPU scratch map to avoid stack overflow (512-byte limit).
	__u32 scratch_key = 0;
	struct wan_egress_parsed *pkt =
		bpf_map_lookup_elem(&wan_egress_scratch_map, &scratch_key);

	if (!pkt)
		return TC_ACT_SHOT;

	/* Initialize scratch bytes for verifier friendliness across subprogram
	 * pointer writes. */
	__builtin_memset(pkt, 0, sizeof(*pkt));
	int ret = parse_wan_egress_packet(skb, link_h_len, pkt);

	if (ret) {
		// Negative return: parsing error - drop
		// Positive return: unsupported protocol or non-initial fragment - pass through
		if (ret < 0) {
			bpf_printk("wan_egress parse error: %d, dropping", ret);
			return TC_ACT_SHOT;
		}
		return TC_ACT_OK;
	}

	if (pkt->l4proto == IPPROTO_TCP)
		return do_tproxy_wan_egress_tcp(skb, link_h_len, &pkt->tuples,
						&pkt->ethh, &pkt->tcph);
	if (pkt->l4proto == IPPROTO_UDP)
		return do_tproxy_wan_egress_udp(skb, link_h_len, &pkt->tuples,
						&pkt->ethh, &pkt->udph);
	return TC_ACT_OK;
}

SEC("tc/wan_egress_l2")
int tproxy_wan_egress_l2(struct __sk_buff *skb)
{
	return do_tproxy_wan_egress(skb, 14);
}

SEC("tc/wan_egress_l3")
int tproxy_wan_egress_l3(struct __sk_buff *skb)
{
	return do_tproxy_wan_egress(skb, 0);
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

SEC("tc/dae0_ingress")
int tproxy_dae0_ingress(struct __sk_buff *skb)
{
	// reverse the tuple!
	struct redirect_tuple redirect_tuple = {};
	int ret;

	ret = load_redirect_tuple(skb, &redirect_tuple);
	if (ret)
		return TC_ACT_OK;
	struct redirect_entry *redirect_entry =
		bpf_map_lookup_elem(&redirect_track, &redirect_tuple);

	if (!redirect_entry)
		return TC_ACT_OK;

	// Update last_seen_ns on each access for accurate TTL tracking
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

// tproxy_sockops is a placeholder for future sockops-based socket tracking.
// Preserved for Go ABI compatibility.
SEC("sockops")
int tproxy_sockops(struct bpf_sock_ops *skops)
{
	return BPF_OK;
}

// tproxy_sk_msg_redir is DISABLED due to kernel panic issues with
// bpf_msg_redirect_hash(). Preserved for Go ABI compatibility.
SEC("sk_msg")
int tproxy_sk_msg_redir(struct sk_msg_md *msg)
{
	return SK_PASS;
}

SEC("license") const char __license[] = "Dual BSD/GPL";
