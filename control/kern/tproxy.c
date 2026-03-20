// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

// +build ignore
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
#define IPV6_MAX_EXTENSIONS 4

#define ipv6_optlen(p) (((p)+1) << 3)

#define TPROXY_MARK 0x8000000

#define NDP_REDIRECT 137

// Param keys:
static const __u32 zero_key;
static const __u32 one_key = 1;

// Outbound Connectivity Map:

struct outbound_connectivity_query {
	__u8 outbound;
	__u8 l4proto;
	__u8 ipversion;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct outbound_connectivity_query);
	__type(value, __u32); // true, false
	__uint(max_entries, 256 * 2 * 2); // outbound * l4proto * ipversion
} outbound_connectivity_map SEC(".maps");

// Sockmap:
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key, __u32); // 0 is tcp, 1 is udp.
	__type(value, __u64); // fd of socket.
	__uint(max_entries, 2);
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

struct dae_param {
	__u32 tproxy_port;
	__u32 control_plane_pid;
	__u32 dae0_ifindex;
	__u32 dae_netns_id;
	__u8 dae0peer_mac[6];
	// use_redirect_peer enables bpf_redirect_peer() optimization for TC ingress.
	// Only safe with: (1) netkit device + scrub=NONE, (2) kernel >= 6.8 (CVE-2025-37959 fix).
	// Egress paths must always use bpf_redirect() (redirect_peer is ingress-only).
	__u8 use_redirect_peer;
	__u8 padding;
};

/* Use const volatile for cilium/ebpf v0.20.0 compatibility.
 * This ensures the variable is placed in .rodata section and
 * can be rewritten from userspace via RewriteConstants. */
const volatile struct dae_param PARAM = {};

// routing_tuples_map: Cache routing results for established flows.
//
// Design rationale:
// - Changed from LRU_HASH to HASH for better performance and semantic correctness.
// - LRU eviction is unsuitable for connection state (should be TTL-based, not access-time-based).
// - Hash map is simpler and faster; userspace janitor handles cleanup via timestamp.
//
// The routing_result struct includes implicit timing via userspace janitor tracking
// last activity. This provides proper connection lifecycle management.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct tuples_key);
	__type(value, struct routing_result);
	__uint(max_entries, MAX_DST_MAPPING_NUM);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} routing_tuples_map SEC(".maps");

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
	__uint(max_entries, 65535);
} fast_sock SEC(".maps");

// Array of LPM tries:
struct lpm_key {
	struct bpf_lpm_trie_key trie_key;
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
	__u32 pid;
	char pname[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct pid_pname);
	__uint(max_entries, MAX_COOKIE_PID_PNAME_MAPPING_NUM);
} cookie_pid_map SEC(".maps");

struct udp_conn_state {
	// For each flow (echo symmetric path), note the original flow direction.
	// Mark as true if traffic go through wan ingress.
	// For traffic from lan that go through wan ingress, dae parse them in lan egress
	bool is_wan_ingress_direction;

	// Last seen timestamp in nanoseconds (bpf_ktime_get_ns()).
	// Userspace janitor periodically cleans up expired entries.
	// This replaces bpf_timer to avoid CVE-2024-41045 and improve hot path performance.
	__u64 last_seen_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DST_MAPPING_NUM);
	__type(key, struct tuples_key);
	__type(value, struct udp_conn_state);
} udp_conn_state_map SEC(".maps");

// tcp_conn_state: Track TCP connection state for lifecycle-based cleanup.
// This enables cascade cleanup of routing_tuples_map when TCP connections close.
// Design consistent with udp_conn_state_map.
struct tcp_conn_state {
	// For each flow (echo symmetric path), note the original flow direction.
	// Mark as true if traffic go through wan ingress.
	bool is_wan_ingress_direction;

	// Connection state: 0 = active, 1 = closing (FIN/RST seen)
	// When in closing state, userspace janitor will clean up both this map
	// and the associated routing_tuples_map entries.
	__u8 state;

	// Last seen timestamp in nanoseconds (bpf_ktime_get_ns()).
	__u64 last_seen_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DST_MAPPING_NUM);
	__type(key, struct tuples_key);
	__type(value, struct tcp_conn_state);
} tcp_conn_state_map SEC(".maps");

// bpf_stats: Map statistics for monitoring and robustness.
// key=0: udp_conn_state_map overflow count (when bpf_map_update_elem fails with -E2BIG)
// key=1: routing_tuples_map overflow count
// key=2: udp_conn_state_map successful updates (for hit rate calculation)
// Userspace reads these counters to detect map pressure and trigger alerts.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 3);
} bpf_stats_map SEC(".maps");

enum bpf_stats_key {
	BPF_STATS_UDP_CONN_OVERFLOW = 0,
	BPF_STATS_ROUTING_OVERFLOW = 1,
	BPF_STATS_TCP_CONN_OVERFLOW = 2,
};

// TCP connection state constants.
enum tcp_state {
	TCP_STATE_ACTIVE = 0,
	TCP_STATE_CLOSING = 1,  // FIN or RST seen
};

// Functions:

static __always_inline __u8 ipv4_get_dscp(const struct iphdr *iph)
{
	return (iph->tos & 0xfc) >> 2;
}

static __always_inline __u8 ipv6_get_dscp(const struct ipv6hdr *ipv6h)
{
	return (ipv6h->priority << 2) | (ipv6h->flow_lbl[0] >> 6);
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

// parse_transport_fast implements direct packet access using bpf_skb_pull_data
// to linearize non-linear data regions, then accesses headers via pointer arithmetic.
//
// Key principles for BPF direct access:
// 1. Use bpf_skb_pull_data to ensure header data is in linear region
// 2. Use pointer arithmetic on skb->data to get header pointers
// 3. Always check (ptr + 1) <= data_end before dereferencing
// 4. Boundary check failures are bad packets, return error (not fallback)
//
// Returns: 0 on success, -1 to fall back to slow path, positive on error
static __always_inline int
parse_transport_fast(struct __sk_buff *skb, __u32 link_h_len,
		     struct ethhdr *ethh, struct iphdr *iph,
		     struct ipv6hdr *ipv6h, struct icmp6hdr *icmp6h,
		     struct tcphdr *tcph, struct udphdr *udph, __u8 *ihl,
		     __u8 *l4proto)
{
	void *data, *data_end;
	__u32 offset = 0;

	*ihl = 0;
	*l4proto = 0;
	__builtin_memset(ethh, 0, sizeof(struct ethhdr));
	__builtin_memset(iph, 0, sizeof(struct iphdr));
	__builtin_memset(ipv6h, 0, sizeof(struct ipv6hdr));
	__builtin_memset(icmp6h, 0, sizeof(struct icmp6hdr));
	__builtin_memset(tcph, 0, sizeof(struct tcphdr));
	__builtin_memset(udph, 0, sizeof(struct udphdr));

	// Pull only the header data we need (not the entire packet).
	// This is more efficient than pulling the whole packet and works
	// even for large packets (e.g., jumbo frames).
	// 512 bytes is enough for: ethhdr(14) + iphdr(60 max with options) +
	// IPv6 ext headers(200) + L4 headers(60) + some extra.
	// If this fails, fall back to slow path which uses bpf_skb_load_bytes.
#define HEADER_PULL_SIZE 512
	if (bpf_skb_pull_data(skb, HEADER_PULL_SIZE))
		return -1;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	// Parse Ethernet header (or L3-only)
	if (link_h_len == ETH_HLEN) {
		struct ethhdr *eth_ptr = data;

		// Boundary check: if this fails, it's a malformed packet, not a
		// non-linear data issue. Return error directly.
		if ((void *)(eth_ptr + 1) > data_end)
			return -EFAULT;

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

		// Boundary check: malformed packet if this fails
		if ((void *)(iph_ptr + 1) > data_end)
			return -EFAULT;

		if (iph_ptr->ihl < 5)
			return -EFAULT;

		__u32 ip_hdr_len = iph_ptr->ihl * 4;
		__u32 l4_offset = offset + ip_hdr_len;

		// Direct field access - more efficient than memcpy
		iph->version = iph_ptr->version;
		iph->ihl = iph_ptr->ihl;
		iph->protocol = iph_ptr->protocol;
		iph->saddr = iph_ptr->saddr;
		iph->daddr = iph_ptr->daddr;
		iph->tos = iph_ptr->tos;
		iph->tot_len = iph_ptr->tot_len;
		*ihl = iph_ptr->ihl;
		*l4proto = iph_ptr->protocol;

		// Parse L4 header with direct access
		// Note: Boundary checks are per-protocol to avoid rejecting valid packets
		// of protocols with smaller headers (e.g., UDP with 8 bytes vs TCP with 20 bytes)
		switch (iph->protocol) {
		case IPPROTO_TCP: {
			// Check if we can access TCP header (20 bytes minimum)
			if (data + l4_offset + sizeof(struct tcphdr) > data_end)
				return -1;  // Fall back to slow path for non-linear or short data
			struct tcphdr *tcph_ptr = data + l4_offset;

			if ((void *)(tcph_ptr + 1) > data_end)
				return -EFAULT;
			tcph->source = tcph_ptr->source;
			tcph->dest = tcph_ptr->dest;
			tcph->seq = tcph_ptr->seq;
			tcph->ack_seq = tcph_ptr->ack_seq;
			tcph->doff = tcph_ptr->doff;
			tcph->rst = tcph_ptr->rst;
			tcph->syn = tcph_ptr->syn;
			tcph->fin = tcph_ptr->fin;
			tcph->window = tcph_ptr->window;
			return 0;
		}
		case IPPROTO_UDP: {
			// Check if we can access UDP header (8 bytes)
			if (data + l4_offset + sizeof(struct udphdr) > data_end)
				return -1;  // Fall back to slow path for non-linear or short data
			struct udphdr *udph_ptr = data + l4_offset;

			if ((void *)(udph_ptr + 1) > data_end)
				return -EFAULT;
			udph->source = udph_ptr->source;
			udph->dest = udph_ptr->dest;
			udph->len = udph_ptr->len;
			udph->check = udph_ptr->check;
			return 0;
		}
		default:
			return 1;
		}
	}

	if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6h_ptr = data + offset;

		// Boundary check for IPv6 header
		if ((void *)(ipv6h_ptr + 1) > data_end)
			return -EFAULT;

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

		// Skip extension headers using direct access (already pulled data)
		__u8 nexthdr = ipv6h_ptr->nexthdr;

		for (int i = 0; i < IPV6_MAX_EXTENSIONS; i++) {
			if (nexthdr == IPPROTO_NONE)
				return -EFAULT;

			if (!is_extension_header(nexthdr))
				break;

			// Check we can access the extension header
			// If we can't, fall back to slow path (data might be non-linear)
			if (data + offset + 2 > data_end)
				return -1;

			// Get next header and extension header length
			const __u8 *ext_hdr = data + offset;

			nexthdr = ext_hdr[0];
			__u8 hdr_ext_len = ext_hdr[1];
			__u32 ext_len = ipv6_optlen(hdr_ext_len);

			// If extension header doesn't fit in pulled data, fall back to slow path
			if (data + offset + ext_len > data_end)
				return -1;

			offset += ext_len;
			*l4proto = nexthdr;
		}

		if (is_extension_header(nexthdr))
			return -EFAULT;

		// Parse L4 header with direct access
		switch (nexthdr) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph_ptr = data + offset;

			if ((void *)(tcph_ptr + 1) > data_end)
				return -EFAULT;
			tcph->source = tcph_ptr->source;
			tcph->dest = tcph_ptr->dest;
			tcph->seq = tcph_ptr->seq;
			tcph->ack_seq = tcph_ptr->ack_seq;
			tcph->doff = tcph_ptr->doff;
			tcph->rst = tcph_ptr->rst;
			tcph->syn = tcph_ptr->syn;
			tcph->fin = tcph_ptr->fin;
			tcph->window = tcph_ptr->window;
			return 0;
		}
		case IPPROTO_UDP: {
			struct udphdr *udph_ptr = data + offset;

			if ((void *)(udph_ptr + 1) > data_end)
				return -EFAULT;
			udph->source = udph_ptr->source;
			udph->dest = udph_ptr->dest;
			udph->len = udph_ptr->len;
			udph->check = udph_ptr->check;
			return 0;
		}
		case IPPROTO_ICMPV6: {
			if (data + offset + sizeof(struct icmp6hdr) > data_end)
				return -EFAULT;
			const struct icmp6hdr *icmp6h_ptr = data + offset;

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
static __always_inline int
parse_transport_slow(struct __sk_buff *skb, __u32 link_h_len,
		     struct ethhdr *ethh, struct iphdr *iph,
		     struct ipv6hdr *ipv6h, struct icmp6hdr *icmp6h,
		     struct tcphdr *tcph, struct udphdr *udph, __u8 *ihl,
		     __u8 *l4proto)
{
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
		offset += iph->ihl * 4;

		*l4proto = iph->protocol;
		switch (iph->protocol) {
		case IPPROTO_TCP:
			ret = bpf_skb_load_bytes(skb, offset, tcph,
						 sizeof(struct tcphdr));
			if (ret)
				return -EFAULT;
			break;
		case IPPROTO_UDP:
			ret = bpf_skb_load_bytes(skb, offset, udph,
						 sizeof(struct udphdr));
			if (ret)
				return -EFAULT;
			break;
		default:
			return 1;
		}
		*ihl = iph->ihl;
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
			return 1;

		*l4proto = nexthdr;
		switch (nexthdr) {
		case IPPROTO_TCP:
			ret = bpf_skb_load_bytes(skb, offset, tcph,
						 sizeof(struct tcphdr));
			if (ret)
				return -EFAULT;
			break;
		case IPPROTO_UDP:
			ret = bpf_skb_load_bytes(skb, offset, udph,
						 sizeof(struct udphdr));
			if (ret)
				return -EFAULT;
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
static __always_inline int
parse_transport(struct __sk_buff *skb, __u32 link_h_len,
		struct ethhdr *ethh, struct iphdr *iph, struct ipv6hdr *ipv6h,
		struct icmp6hdr *icmp6h, struct tcphdr *tcph,
		struct udphdr *udph, __u8 *ihl, __u8 *l4proto)
{
	int ret = parse_transport_fast(skb, link_h_len, ethh, iph, ipv6h,
				       icmp6h, tcph, udph, ihl, l4proto);
	if (ret == -1) {
		// Fast path failed (pull failed or headers too large),
		// fall back to slow path using bpf_skb_load_bytes.
		return parse_transport_slow(skb, link_h_len, ethh, iph, ipv6h,
					    icmp6h, tcph, udph, ihl, l4proto);
	}
	return ret;
}

struct lan_ingress_parsed {
	struct ethhdr ethh;
	struct tuples tuples;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 l4proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct lan_ingress_parsed);
	__uint(max_entries, 1);
} lan_ingress_scratch_map SEC(".maps");

static __noinline int
parse_lan_ingress_packet(struct __sk_buff *skb, u32 link_h_len,
			 struct lan_ingress_parsed *out)
{
	struct ethhdr ethh;
	struct iphdr iph;
	struct ipv6hdr ipv6h;
	struct icmp6hdr icmp6h;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 ihl;
	__u8 l4proto;
	int ret = parse_transport(skb, link_h_len, &ethh, &iph, &ipv6h, &icmp6h,
				  &tcph, &udph, &ihl, &l4proto);

	if (ret)
		return ret;
	if (l4proto == IPPROTO_ICMPV6)
		return 1;

	__builtin_memset(out, 0, sizeof(*out));
	out->ethh = ethh;
	out->tcph = tcph;
	out->udph = udph;
	out->l4proto = l4proto;
	get_tuples(skb, &out->tuples, &iph, &ipv6h, &tcph, &udph, l4proto);
	return 0;
}

struct wan_egress_parsed {
	struct ethhdr ethh;
	struct tuples tuples;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 l4proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct wan_egress_parsed);
	__uint(max_entries, 1);
} wan_egress_scratch_map SEC(".maps");

static __noinline int
parse_wan_egress_packet(struct __sk_buff *skb, u32 link_h_len,
			struct wan_egress_parsed *out)
{
	struct ethhdr ethh;
	struct iphdr iph;
	struct ipv6hdr ipv6h;
	struct icmp6hdr icmp6h;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 ihl;
	__u8 l4proto;
	int ret = parse_transport(skb, link_h_len, &ethh, &iph, &ipv6h, &icmp6h,
				  &tcph, &udph, &ihl, &l4proto);

	if (ret)
		return ret;
	if (l4proto == IPPROTO_ICMPV6)
		return 1;

	__builtin_memset(out, 0, sizeof(*out));
	out->ethh = ethh;
	out->tcph = tcph;
	out->udph = udph;
	out->l4proto = l4proto;
	get_tuples(skb, &out->tuples, &iph, &ipv6h, &tcph, &udph, l4proto);
	return 0;
}

struct route_params {
	__u32 flag[8];
	__u8  is_wan;         // Independent field to indicate WAN direction
	const void *l4hdr;
	const __be32 *saddr;
	const __be32 *daddr;
	__be32 mac[4];
};

struct route_ctx {
	const struct route_params *params;
	__u16 h_dport;
	__u16 h_sport;
	__s64 result; // high -> low: sign(1b) unused(23b) mark(32b) outbound(8b)
	struct lpm_key lpm_key_saddr, lpm_key_daddr, lpm_key_mac;
	__u32 domain_word_idx;
	__u32 domain_word_bits;
	bool domain_word_cached;
	volatile __u8 route_state;
};

enum route_state_flags {
	ROUTE_STATE_BAD_RULE = 1U << 0,
	ROUTE_STATE_GOOD_SUBRULE = 1U << 1,
	ROUTE_STATE_MUST = 1U << 2,
	ROUTE_STATE_DNS_QUERY = 1U << 3,
};

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
		domain_routing = bpf_map_lookup_elem(&domain_routing_map,
						     ctx->params->daddr);
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
	struct route_ctx *ctx = data;
	struct match_set *match_set;
	__u8 l4proto_type = ctx->params->flag[0];
	__u8 ipversion_type = ctx->params->flag[1];
	const __u32 *pname = &ctx->params->flag[2];
	__u8 is_wan = ctx->params->is_wan;
	__u8 dscp = ctx->params->flag[6];

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

static __noinline __s64 route(const struct route_params *params)
{
#define _l4proto_type params->flag[0]
#define _ipversion_type params->flag[1]
#define _pname (&params->flag[2])
#define _is_wan params->is_wan
#define _dscp params->flag[6]

	int ret;
	struct route_ctx ctx;

	__builtin_memset(&ctx, 0, sizeof(ctx));
	ctx.params = params;
	ctx.result = -ENOEXEC;

	// Variables for further use.
	if (_l4proto_type == L4ProtoType_TCP) {
		ctx.h_dport = bpf_ntohs(((struct tcphdr *)params->l4hdr)->dest);
		ctx.h_sport =
			bpf_ntohs(((struct tcphdr *)params->l4hdr)->source);
	} else {
		ctx.h_dport = bpf_ntohs(((struct udphdr *)params->l4hdr)->dest);
		ctx.h_sport =
			bpf_ntohs(((struct udphdr *)params->l4hdr)->source);
	}

	// Rule is like: domain(suffix:baidu.com, suffix:google.com) && port(443) ->
	// proxy Subrule is like: domain(suffix:baidu.com, suffix:google.com) Match
	// set is like: suffix:baidu.com
	ctx.route_state =
		(ctx.h_dport == 53 &&
		 (_l4proto_type == L4ProtoType_UDP ||
		  _l4proto_type == L4ProtoType_TCP))
		? ROUTE_STATE_DNS_QUERY
		: 0;

	struct lpm_key lpm_key_saddr = {
		.trie_key = { IPV6_BYTE_LENGTH * 8, {} },
	};
	ctx.lpm_key_saddr = lpm_key_saddr;
	struct lpm_key lpm_key_daddr = {
		.trie_key = { IPV6_BYTE_LENGTH * 8, {} },
	};
	ctx.lpm_key_daddr = lpm_key_daddr;
	struct lpm_key lpm_key_mac = {
		.trie_key = { IPV6_BYTE_LENGTH * 8, {} },
	};
	ctx.lpm_key_mac = lpm_key_mac;
	__builtin_memcpy(ctx.lpm_key_saddr.data, params->saddr,
			 IPV6_BYTE_LENGTH);
	__builtin_memcpy(ctx.lpm_key_daddr.data, params->daddr,
			 IPV6_BYTE_LENGTH);
	__builtin_memcpy(ctx.lpm_key_mac.data, params->mac, IPV6_BYTE_LENGTH);

	__u32 active_rules_len = MAX_MATCH_SET_LEN;
	__u32 *active_rules_len_ptr =
		bpf_map_lookup_elem(&routing_meta_map, &zero_key);
	if (active_rules_len_ptr && *active_rules_len_ptr > 0 &&
	    *active_rules_len_ptr <= MAX_MATCH_SET_LEN)
		active_rules_len = *active_rules_len_ptr;

	ret = bpf_loop(active_rules_len, route_loop_cb, &ctx, 0);
	if (unlikely(ret < 0))
		return ret;
	if (ctx.result >= 0)
		return ctx.result;
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

	if (l4proto == IPPROTO_TCP)
		sk = bpf_map_lookup_elem(&listen_socket_map, &zero_key);
	else
		sk = bpf_map_lookup_elem(&listen_socket_map, &one_key);

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

static __always_inline int prep_redirect_to_control_plane(
	struct __sk_buff *skb, __u32 link_h_len, struct tuples *tuples,
	__u8 l4proto, struct ethhdr *ethh, __u8 from_wan, struct tcphdr *tcph)
{
	struct redirect_tuple redirect_tuple = {};
	struct redirect_entry redirect_entry = {};

	if (!link_h_len) {
		__u16 l3proto = skb->protocol;
		int ret;

		// Expand packet head to add Ethernet header
		ret = bpf_skb_change_head(skb, sizeof(struct ethhdr), 0);
		if (ret) {
			// Failed to expand packet - this can happen under memory pressure
			// Log and return error so caller can handle gracefully
			bpf_printk("prep_redirect: bpf_skb_change_head failed: %d", ret);
			return ret;
		}
		bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
				    &l3proto, sizeof(l3proto), 0);
	}

	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
			    (void *)&PARAM.dae0peer_mac, 6, 0);

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		// Use IPv4-mapped IPv6 format with ffff marker to avoid collision
		// with IPv6 addresses like ::a.b.c.d
		redirect_tuple.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple.sip.u6_addr32[3] = tuples->five.sip.u6_addr32[3];
		redirect_tuple.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple.dip.u6_addr32[3] = tuples->five.dip.u6_addr32[3];
	} else {
		__builtin_memcpy(&redirect_tuple.sip, &tuples->five.sip, IPV6_BYTE_LENGTH);
		__builtin_memcpy(&redirect_tuple.dip, &tuples->five.dip, IPV6_BYTE_LENGTH);
	}

	redirect_entry.ifindex = skb->ifindex;
	redirect_entry.from_wan = from_wan;
	redirect_entry.last_seen_ns = bpf_ktime_get_ns();  // Set timestamp for janitor
	if (link_h_len == ETH_HLEN) {
		__builtin_memcpy(redirect_entry.smac, ethh->h_source, 6);
		__builtin_memcpy(redirect_entry.dmac, ethh->h_dest, 6);
	} else {
		__builtin_memset(redirect_entry.smac, 0, 6);
		__builtin_memset(redirect_entry.dmac, 0, 6);
	}
	bpf_map_update_elem(&redirect_track, &redirect_tuple, &redirect_entry, BPF_ANY);

	skb->cb[0] = TPROXY_MARK;
	skb->cb[1] = 0;
	if ((l4proto == IPPROTO_TCP && tcph->syn) || l4proto == IPPROTO_UDP)
		skb->cb[1] = l4proto;

	return 0;  // Success
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
// Uses timestamp-based lazy deletion with userspace janitor cleanup.
//
// Design choice: Kernel path only updates timestamps, userspace handles expiry.
// This avoids:
// - Hot path overhead of expiry checks on every packet
// - Complex cascade deletion of routing_tuples_map in kernel
// - Clock synchronization issues between kernel/userspace
//
// Robustness: If map is full (E2BIG), we increment overflow counter and return NULL.
// Callers should gracefully degrade: continue processing without conntrack state
// rather than dropping packets.
static __always_inline struct udp_conn_state *
mark_udp_seen(struct tuples_key *key, bool is_wan_ingress_direction)
{
	struct udp_conn_state *state = bpf_map_lookup_elem(&udp_conn_state_map, key);
	__u64 now = bpf_ktime_get_ns();

	if (state) {
		// Fast path: update timestamp and return
		state->last_seen_ns = now;
		return state;
	}

	// Slow path: create new entry (either no entry or expired one was deleted)
	struct udp_conn_state new_state = {
		.is_wan_ingress_direction = is_wan_ingress_direction,
		.last_seen_ns = now,
	};

	int ret = bpf_map_update_elem(&udp_conn_state_map, key, &new_state, BPF_ANY);

	if (unlikely(ret)) {
		// Map full or other error: increment overflow counter for monitoring
		// Return NULL to signal caller to degrade gracefully
		__u32 stats_key = BPF_STATS_UDP_CONN_OVERFLOW;
		__u64 *overflow_count = bpf_map_lookup_elem(&bpf_stats_map, &stats_key);

		if (overflow_count)
			__sync_fetch_and_add(overflow_count, 1);
		return NULL;
	}

	return bpf_map_lookup_elem(&udp_conn_state_map, key);
}

// mark_tcp_seen updates TCP connection state for lifecycle tracking.
// Uses timestamp-based lazy deletion with userspace janitor cleanup.
//
// Design choice: Kernel path only updates timestamps and tracks TCP state,
// userspace handles expiry. This avoids hot path overhead and complex
// cascade deletion of routing_tuples_map in kernel.
//
// State transitions:
// - SYN -> TCP_STATE_ACTIVE
// - FIN/RST -> TCP_STATE_CLOSING
//
// Returns state pointer, or NULL if map full (caller should degrade gracefully)
static __always_inline struct tcp_conn_state *
mark_tcp_seen(struct tuples_key *key, const struct tcphdr *tcph,
	      bool is_wan_ingress_direction)
{
	struct tcp_conn_state *state = bpf_map_lookup_elem(&tcp_conn_state_map, key);
	__u64 now = bpf_ktime_get_ns();

	if (state) {
		// Fast path: update timestamp and track TCP state
		state->last_seen_ns = now;

		// Check for connection close signals (FIN or RST)
		if (tcph->fin || tcph->rst)
			state->state = TCP_STATE_CLOSING;

		return state;
	}

	// Only create new entry on SYN (new connection)
	if (tcph->syn && !tcph->ack) {
		// Slow path: create new entry
		struct tcp_conn_state new_state = {
			.is_wan_ingress_direction = is_wan_ingress_direction,
			.state = TCP_STATE_ACTIVE,
			.last_seen_ns = now,
		};

		int ret = bpf_map_update_elem(&tcp_conn_state_map, key, &new_state, BPF_ANY);

		if (unlikely(ret)) {
			// Map full or other error: increment overflow counter
			__u32 stats_key = BPF_STATS_TCP_CONN_OVERFLOW;
			__u64 *overflow_count = bpf_map_lookup_elem(&bpf_stats_map, &stats_key);

			if (overflow_count)
				__sync_fetch_and_add(overflow_count, 1);
			return NULL;
		}

		return bpf_map_lookup_elem(&tcp_conn_state_map, key);
	}

	// Hot reload mitigation: For non-SYN packets without existing state,
	// create a temporary entry to capture FIN/RST signals.
	// This handles connections that existed before BPF program reload.
	if (tcph->ack || tcph->fin || tcph->rst || tcph->psh) {
		struct tcp_conn_state temp_state = {
			.is_wan_ingress_direction = is_wan_ingress_direction,
			.state = tcph->fin || tcph->rst ? TCP_STATE_CLOSING : TCP_STATE_ACTIVE,
			.last_seen_ns = now,
		};

		int ret = bpf_map_update_elem(&tcp_conn_state_map, key, &temp_state,
					     BPF_NOEXIST);  // Only create if not exists

		if (ret == 0) {  // Successfully created
			return bpf_map_lookup_elem(&tcp_conn_state_map, key);
		}
		// If creation failed (map full or race), continue without state tracking
	}

	// Non-SYN packet without existing state: ignore
	return NULL;
}

static __always_inline bool
load_cached_routing_result(struct tuples_key *five_tuple, __u8 *outbound,
			   __u32 *mark, bool *must)
{
	struct routing_result *routing_result =
		bpf_map_lookup_elem(&routing_tuples_map, five_tuple);

	if (!routing_result)
		return false;
	*outbound = routing_result->outbound;
	*mark = routing_result->mark;
	*must = routing_result->must;
	return true;
}

static __always_inline bool is_new_tcp_connection(const struct tcphdr *tcph)
{
	return tcph->syn && !tcph->ack;
}

// Unified non-syn TCP handling entry for WAN egress.
// Keep main-equivalent behavior:
// - Reuse cached routing result for established connections.
// - If no cache, do not affect pre-existing/server-side flows.
static __always_inline bool
load_non_syn_tcp_wan_egress(struct tuples_key *five_tuple, __u8 *outbound,
			    __u32 *mark, bool *must)
{
	return load_cached_routing_result(five_tuple, outbound, mark, must);
}

static __noinline int do_tproxy_lan_egress(struct __sk_buff *skb, u32 link_h_len)
{
	struct ethhdr ethh;
	struct iphdr iph;
	struct ipv6hdr ipv6h;
	struct icmp6hdr icmp6h;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 ihl;
	__u8 l4proto;

	int ret = parse_transport(skb, link_h_len, &ethh, &iph, &ipv6h, &icmp6h,
				  &tcph, &udph, &ihl, &l4proto);
	if (ret) {
		bpf_printk("parse_transport: %d", ret);
		return TC_ACT_OK;
	}

	if (skb->ingress_ifindex == NOWHERE_IFINDEX &&  // Only drop NDP_REDIRECT packets from localhost
		l4proto == IPPROTO_ICMPV6 && icmp6h.icmp6_type == NDP_REDIRECT) {
		// REDIRECT (NDP)
		return TC_ACT_SHOT;
	}

	// Update UDP Conntrack
	if (l4proto == IPPROTO_UDP) {
		// DNS traffic is short-lived and stateless in our fast path.
		// Skip tuple build + conntrack update to reduce state churn.
		if (udph.source == bpf_htons(53) || udph.dest == bpf_htons(53))
			return TC_ACT_PIPE;

		struct tuples tuples;
		struct tuples_key reversed_tuples_key;

		get_tuples(skb, &tuples, &iph, &ipv6h, &tcph, &udph, l4proto);
		copy_reversed_tuples(&tuples.five, &reversed_tuples_key);
		// Robustness: If conntrack map is full, gracefully degrade by continuing
		// without state tracking. This is acceptable as the packet will be processed
		// normally; we just lose connection tracking optimization.
		mark_udp_seen(&reversed_tuples_key, true);
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

static __noinline int do_tproxy_lan_ingress(struct __sk_buff *skb, u32 link_h_len)
{
	__u32 scratch_key = 0;
	struct lan_ingress_parsed *pkt =
		bpf_map_lookup_elem(&lan_ingress_scratch_map, &scratch_key);

	if (unlikely(!pkt))
		return TC_ACT_SHOT;

	/* Ensure scratch bytes are initialized even if verifier can't precisely
	 * track writes done through callee pointer arguments. */
	__builtin_memset(pkt, 0, sizeof(*pkt));
	int ret = parse_lan_ingress_packet(skb, link_h_len, pkt);

	if (ret) {
		if (ret < 0)
			bpf_printk("parse_transport error");
		return TC_ACT_OK;
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
		bool must;

		// Track TCP connection state (update timestamp, detect FIN/RST)
		mark_tcp_seen(&pkt->tuples.five, &pkt->tcph, false);

		/*
		 * Compatibility restore for 030902f behavior and align with WAN
		 * non-SYN session handling: reuse cached routing result for
		 * established TCP packets.
		 */
		if (!load_cached_routing_result(&pkt->tuples.five, &outbound, &mark,
						&must)) {
			/* No cache: keep historical direct-pass semantics (e.g.
			 * single-arm / reply-path traffic).
			 */
			return TC_ACT_OK;
		}

		skb->mark = mark;
		if (outbound == OUTBOUND_DIRECT)
			return TC_ACT_OK;
		if (unlikely(outbound == OUTBOUND_BLOCK))
			return TC_ACT_SHOT;
		if (!wan_outbound_is_alive(skb, outbound, pkt->l4proto,
					   pkt->tuples.five.dport))
			return TC_ACT_SHOT;
		goto control_plane;
	}

	// Routing for new connection.
	struct route_params params;

	__builtin_memset(&params, 0, sizeof(params));

	if (pkt->l4proto == IPPROTO_TCP) {
		params.l4hdr = &pkt->tcph;
		params.flag[0] = L4ProtoType_TCP;
	} else {
		if (!is_short_lived_udp_traffic(&pkt->tuples.five)) {
			struct udp_conn_state *conn_state =
				mark_udp_seen(&pkt->tuples.five, false);
			// Robustness: If conntrack map is full (conn_state == NULL),
			// gracefully degrade by continuing with normal routing instead of
			// dropping the packet. We lose the "direct return path" optimization
			// for reply packets, but service continues.
			if (conn_state && conn_state->is_wan_ingress_direction) {
				// Replay (outbound) of an inbound flow => direct.
				return TC_ACT_OK;
			}
		}
		params.l4hdr = &pkt->udph;
		params.flag[0] = L4ProtoType_UDP;
	}
	params.flag[1] = (skb->protocol == bpf_htons(ETH_P_IP)) ? IpVersionType_4 : IpVersionType_6;
	params.flag[6] = pkt->tuples.dscp;
	params.mac[2] =
		bpf_htonl((pkt->ethh.h_source[0] << 8) | (pkt->ethh.h_source[1]));
	params.mac[3] = bpf_htonl((pkt->ethh.h_source[2] << 24) |
			  (pkt->ethh.h_source[3] << 16) |
			  (pkt->ethh.h_source[4] << 8) | (pkt->ethh.h_source[5]));
	params.saddr = pkt->tuples.five.sip.u6_addr32;
	params.daddr = pkt->tuples.five.dip.u6_addr32;
	__s64 s64_ret;

	s64_ret = route(&params);
	if (s64_ret < 0) {
		bpf_printk("shot routing: %d", s64_ret);
		return TC_ACT_SHOT;
	}

	struct routing_result routing_result = { 0 };

	routing_result.outbound = s64_ret & 0xff;
	routing_result.mark = s64_ret >> 8;
	routing_result.must = (s64_ret >> 40) & 1;
	routing_result.dscp = pkt->tuples.dscp;
	__builtin_memcpy(routing_result.mac, pkt->ethh.h_source,
			 sizeof(routing_result.mac));
	/// NOTICE: No pid pname info for LAN packet.
	// // Maybe this packet is also in the host (such as docker) ?
	// // I tried and it is false.
	//__u64 cookie = bpf_get_socket_cookie(skb);
	//struct pid_pname *pid_pname =
	//	bpf_map_lookup_elem(&cookie_pid_map, &cookie);
	//if (pid_pname) {
	//	__builtin_memcpy(routing_result.pname, pid_pname->pname,
	//			 TASK_COMM_LEN);
	//	routing_result.pid = pid_pname->pid;
	//}

	// Save routing result.
	if (pkt->l4proto == IPPROTO_UDP &&
	    is_short_lived_udp_traffic(&pkt->tuples.five)) {
		// Skip cache for short-lived DNS to avoid map churn.
	} else {
		ret = bpf_map_update_elem(&routing_tuples_map, &pkt->tuples.five,
					  &routing_result, BPF_ANY);
		if (ret) {
			// Robustness: If routing cache map is full, increment overflow counter
			// and continue without caching. The packet is still processed correctly,
			// we just lose the routing optimization for this flow.
			__u32 stats_key = BPF_STATS_ROUTING_OVERFLOW;
			__u64 *overflow_count = bpf_map_lookup_elem(&bpf_stats_map, &stats_key);

			if (overflow_count)
				__sync_fetch_and_add(overflow_count, 1);
			bpf_printk("routing cache full, continuing without cache: %d", ret);
			// Don't return TC_ACT_SHOT - continue processing the packet
		}
	}
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
	if (pkt->l4proto == IPPROTO_TCP) {
		bpf_printk("tcp(lan): outbound: %u, target: %pI6:%u", ret,
			   pkt->tuples.five.dip.u6_addr32,
			   bpf_ntohs(pkt->tuples.five.dport));
	} else {
		bpf_printk("udp(lan): outbound: %u, target: %pI6:%u",
			   routing_result.outbound, pkt->tuples.five.dip.u6_addr32,
			   bpf_ntohs(pkt->tuples.five.dport));
	}
#endif

	if (routing_result.outbound == OUTBOUND_DIRECT) {
		skb->mark = routing_result.mark;
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("GO OUTBOUND_DIRECT");
#endif
		goto direct;
	} else if (unlikely(routing_result.outbound == OUTBOUND_BLOCK)) {
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("SHOT OUTBOUND_BLOCK");
#endif
		goto block;
	}

	if (!wan_outbound_is_alive(skb, routing_result.outbound, pkt->l4proto,
				   pkt->tuples.five.dport))
		goto block;

	// Assign to control plane.
control_plane:
	if (prep_redirect_to_control_plane(skb, link_h_len, &pkt->tuples, pkt->l4proto,
					   &pkt->ethh, 0, &pkt->tcph)) {
		// Failed to prepare packet (e.g., bpf_skb_change_head failed under memory pressure)
		// Fall back to direct pass to avoid packet corruption
		return TC_ACT_OK;
	}
	return redirect_to_control_plane_ingress();

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
	if ((skb->mark & 0x100) == 0x100)
		return true;
	return false;
}

static __noinline int do_tproxy_wan_ingress(struct __sk_buff *skb, u32 link_h_len)
{
	struct ethhdr ethh;
	struct iphdr iph;
	struct ipv6hdr ipv6h;
	struct icmp6hdr icmp6h;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 ihl;
	__u8 l4proto;

	int ret = parse_transport(skb, link_h_len, &ethh, &iph, &ipv6h, &icmp6h,
				  &tcph, &udph, &ihl, &l4proto);
	if (ret) {
		bpf_printk("parse_transport: %d", ret);
		return TC_ACT_OK;
	}

	// Update UDP Conntrack
	if (l4proto == IPPROTO_UDP) {
		// DNS traffic is short-lived and stateless in our fast path.
		// Skip tuple build + conntrack update to reduce state churn.
		if (udph.source == bpf_htons(53) || udph.dest == bpf_htons(53))
			return TC_ACT_PIPE;

		struct tuples tuples;
		struct tuples_key reversed_tuples_key;

		get_tuples(skb, &tuples, &iph, &ipv6h, &tcph, &udph, l4proto);
		copy_reversed_tuples(&tuples.five, &reversed_tuples_key);
		// Robustness: If conntrack map is full, gracefully degrade by continuing
		// without state tracking. This is acceptable as the packet will be processed
		// normally; we just lose connection tracking optimization.
		mark_udp_seen(&reversed_tuples_key, true);
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
	struct outbound_connectivity_query q = { 0 };
	__u32 *alive;

	q.outbound = outbound;
	q.ipversion = skb->protocol == bpf_htons(ETH_P_IP) ? 4 : 6;
	q.l4proto = l4proto;
	alive = bpf_map_lookup_elem(&outbound_connectivity_map, &q);
	if (alive && *alive == 0 &&
	    !((l4proto == IPPROTO_UDP || l4proto == IPPROTO_TCP) && dport == bpf_htons(53))) {
		// Outbound is not alive. Dns is an exception.
		return false;
	}
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

	if (unlikely(tcp_state_syn)) {
		// New TCP connection.
		struct route_params params;

		__builtin_memset(&params, 0, sizeof(params));
		params.l4hdr = tcph;
		params.flag[0] = L4ProtoType_TCP;
		if (skb->protocol == bpf_htons(ETH_P_IP))
			params.flag[1] = IpVersionType_4;
		else
			params.flag[1] = IpVersionType_6;
		params.flag[6] = tuples->dscp;
		if (pid_is_control_plane(skb, &pid_pname)) {
			// From control plane. Direct.
			return TC_ACT_OK;
		}
		if (pid_pname) {
			// 2, 3, 4, 5
			__builtin_memcpy(&params.flag[2], pid_pname->pname,
					 TASK_COMM_LEN);
		}
		params.is_wan = 1;  // WAN egress direction
		if (link_h_len == ETH_HLEN) {
			params.mac[2] = bpf_htonl((ethh->h_source[0] << 8) | (ethh->h_source[1]));
			params.mac[3] = bpf_htonl((ethh->h_source[2] << 24) |
						  (ethh->h_source[3] << 16) |
						  (ethh->h_source[4] << 8) |
						  (ethh->h_source[5]));
		}
		params.saddr = tuples->five.sip.u6_addr32;
		params.daddr = tuples->five.dip.u6_addr32;

		__s64 s64_ret = route(&params);

		if (s64_ret < 0) {
			bpf_printk("shot routing: %d", s64_ret);
			return TC_ACT_SHOT;
		}

		outbound = s64_ret & 0xff;
		mark = s64_ret >> 8;
		must = (s64_ret >> 40) & 1;

#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		// Print only new connection.
		__u32 pid = pid_pname ? pid_pname->pid : 0;

		bpf_printk("tcp(wan): from %pI6:%u [PID %u]",
			   tuples->five.sip.u6_addr32,
			   bpf_ntohs(tuples->five.sport), pid);
		bpf_printk("tcp(wan): outbound: %u, %pI6:%u", outbound,
			   tuples->five.dip.u6_addr32,
			   bpf_ntohs(tuples->five.dport));
#endif
	} else {
		// Existing TCP connection.
		// Track TCP connection state (update timestamp, detect FIN/RST)
		mark_tcp_seen(&tuples->five, tcph, false);

		if (!load_non_syn_tcp_wan_egress(&tuples->five, &outbound, &mark,
						 &must)) {
			// No cached routing. This is a pre-existing connection
			// or server connection. Let it pass.
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

	if (unlikely(tcp_state_syn)) {
		// Only save non-direct routing to avoid conflicts with LAN ingress.
		// Direct traffic doesn't need control plane processing.
		if (outbound != OUTBOUND_DIRECT || mark != 0 || must) {
			struct routing_result routing_result = {};

			routing_result.outbound = outbound;
			routing_result.mark = mark;
			routing_result.must = must;
			routing_result.dscp = tuples->dscp;
			if (link_h_len == ETH_HLEN)
				__builtin_memcpy(routing_result.mac, ethh->h_source,
						 sizeof(ethh->h_source));
			if (pid_pname) {
				__builtin_memcpy(routing_result.pname,
						 pid_pname->pname,
						 TASK_COMM_LEN);
				routing_result.pid = pid_pname->pid;
			}
			// Write to routing cache and track overflow for monitoring
			int ret = bpf_map_update_elem(&routing_tuples_map, &tuples->five,
						    &routing_result, BPF_ANY);
			if (ret) {
				// Robustness: If routing cache map is full, increment overflow counter
				// and continue without caching. The packet is still processed correctly,
				// we just lose the routing optimization for this flow.
				__u32 stats_key = BPF_STATS_ROUTING_OVERFLOW;
				__u64 *overflow_count = bpf_map_lookup_elem(
						&bpf_stats_map, &stats_key);

				if (overflow_count)
					__sync_fetch_and_add(overflow_count, 1);
				bpf_printk("WAN routing cache full: %d", ret);
				// Don't return TC_ACT_SHOT - continue processing the packet
			}
		}
	}

	if (prep_redirect_to_control_plane(skb, link_h_len, tuples, IPPROTO_TCP, ethh,
					   1, tcph)) {
		// Failed to prepare packet (e.g., bpf_skb_change_head failed)
		// Fall back to direct pass to avoid packet corruption
		return TC_ACT_OK;
	}
	return redirect_to_control_plane_egress();
}

static __noinline int
do_tproxy_wan_egress_udp(struct __sk_buff *skb, u32 link_h_len,
			 struct tuples *tuples, struct ethhdr *ethh,
			 struct udphdr *udph)
{
	// Routing. It decides if we redirect traffic to control plane.
	struct route_params params;
	struct pid_pname *pid_pname;
	__u8 outbound;
	__u32 mark;
	bool must;
	struct tcphdr dummy_tcph = {};

	__builtin_memset(&params, 0, sizeof(params));
	params.l4hdr = udph;
	params.flag[0] = L4ProtoType_UDP;
	if (skb->protocol == bpf_htons(ETH_P_IP))
		params.flag[1] = IpVersionType_4;
	else
		params.flag[1] = IpVersionType_6;
	params.flag[6] = tuples->dscp;

	if (pid_is_control_plane(skb, &pid_pname)) {
		// From control plane => direct.
		return TC_ACT_OK;
	}

	if (!is_short_lived_udp_traffic(&tuples->five)) {
		struct udp_conn_state *conn_state =
			mark_udp_seen(&tuples->five, false);
		// Robustness: If conntrack map is full, gracefully degrade by continuing
		// with normal routing. We lose the direct return path optimization but
		// service continues.
		if (conn_state && conn_state->is_wan_ingress_direction) {
			// Replay (outbound) of an inbound flow => direct.
			return TC_ACT_OK;
		}
	}

	if (pid_pname) {
		// 2, 3, 4, 5
		__builtin_memcpy(&params.flag[2], pid_pname->pname,
				 TASK_COMM_LEN);
	}
	params.is_wan = 1;  // WAN egress direction
	if (ethh) {
		params.mac[2] = bpf_htonl((ethh->h_source[0] << 8) | (ethh->h_source[1]));
		params.mac[3] = bpf_htonl((ethh->h_source[2] << 24) |
					  (ethh->h_source[3] << 16) |
					  (ethh->h_source[4] << 8) |
					  (ethh->h_source[5]));
	}
	params.saddr = tuples->five.sip.u6_addr32;
	params.daddr = tuples->five.dip.u6_addr32;

	__s64 s64_ret = route(&params);

	if (s64_ret < 0) {
		bpf_printk("shot routing: %d", s64_ret);
		return TC_ACT_SHOT;
	}

	// Extract routing values.
	outbound = s64_ret & 0xff;
	mark = s64_ret >> 8;
	must = (s64_ret >> 40) & 1;

	// Only save non-direct routing to avoid conflicts with LAN ingress.
	// Direct traffic doesn't need control plane processing.
	if (outbound != OUTBOUND_DIRECT || mark != 0 || must) {
		if (tuples->five.dport == bpf_htons(53)) {
			// Skip cache for DNS queries.
		} else {
			// Construct new hdr to encap.
			struct routing_result routing_result = {};

			routing_result.outbound = outbound;
			routing_result.mark = mark;
			routing_result.must = must;
			routing_result.dscp = tuples->dscp;
			if (link_h_len == ETH_HLEN)
				__builtin_memcpy(routing_result.mac, ethh->h_source,
						 sizeof(ethh->h_source));
			if (pid_pname) {
				__builtin_memcpy(routing_result.pname,
						 pid_pname->pname,
						 TASK_COMM_LEN);
				routing_result.pid = pid_pname->pid;
			}
			// Write to routing cache and track overflow for monitoring
			int ret = bpf_map_update_elem(&routing_tuples_map, &tuples->five,
						    &routing_result, BPF_ANY);
			if (ret) {
				// Robustness: If routing cache map is full, increment overflow counter
				// and continue without caching. The packet is still processed correctly,
				// we just lose the routing optimization for this flow.
				__u32 stats_key = BPF_STATS_ROUTING_OVERFLOW;
				__u64 *overflow_count = bpf_map_lookup_elem(
						&bpf_stats_map, &stats_key);

				if (overflow_count)
					__sync_fetch_and_add(overflow_count, 1);
				bpf_printk("WAN routing cache full: %d", ret);
				// Don't return TC_ACT_SHOT - continue processing the packet
			}
		}
	}
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
	__u32 pid = pid_pname ? pid_pname->pid : 0;

	bpf_printk("udp(wan): from %pI6:%u [PID %u]", tuples->five.sip.u6_addr32,
		   bpf_ntohs(tuples->five.sport), pid);
	bpf_printk("udp(wan): outbound: %u, %pI6:%u", outbound,
		   tuples->five.dip.u6_addr32, bpf_ntohs(tuples->five.dport));
#endif

	if (outbound == OUTBOUND_DIRECT &&
	    mark == 0 // If mark is not zero, we should re-route it.
	) {
		return TC_ACT_OK;
	} else if (unlikely(outbound == OUTBOUND_BLOCK)) {
		return TC_ACT_SHOT;
	}

	if (!wan_outbound_is_alive(skb, outbound, IPPROTO_UDP,
				   tuples->five.dport))
		return TC_ACT_SHOT;

	if (prep_redirect_to_control_plane(skb, link_h_len, tuples, IPPROTO_UDP, ethh,
					   1, &dummy_tcph)) {
		// Failed to prepare packet (e.g., bpf_skb_change_head failed)
		// Fall back to direct pass to avoid packet corruption
		return TC_ACT_OK;
	}
	return redirect_to_control_plane_egress();
}

/*
 * Keep wan_egress as a BPF subprogram to avoid verifier state explosion on
 * newer kernels (e.g. Debian 6.12), while preserving routing semantics.
 */
static __noinline int do_tproxy_wan_egress(struct __sk_buff *skb, u32 link_h_len)
{
	// Skip packets not from localhost.
	if (skb->ingress_ifindex != NOWHERE_IFINDEX)
		return TC_ACT_OK;

	__u32 scratch_key = 0;
	struct wan_egress_parsed *pkt =
		bpf_map_lookup_elem(&wan_egress_scratch_map, &scratch_key);
	if (unlikely(!pkt))
		return TC_ACT_SHOT;

	/* Initialize stack bytes for verifier friendliness across subprogram
	 * pointer writes. */
	__builtin_memset(pkt, 0, sizeof(*pkt));
	int ret = parse_wan_egress_packet(skb, link_h_len, pkt);

	if (ret)
		return TC_ACT_OK;

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

	/* l4proto is stored in skb->cb[1] only for UDP and new TCP. As for
   * established TCP, kernel can take care of socket lookup, so just
   * return them to stack without calling bpf_sk_assign.
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

/// Parse command line arguments to get the real command name and tgid.
static __always_inline int get_pid_pname(struct pid_pname *pid_pname)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	pid_pname->pid = pid_tgid >> 32;
	if (bpf_get_current_comm(&pid_pname->pname, sizeof(pid_pname->pname)))
		pid_pname->pname[0] = '\0';
	return 0;
}

static __always_inline int _update_map_elem_by_cookie(const __u64 cookie)
{
	if (unlikely(!cookie)) {
		bpf_printk("zero cookie");
		return -EINVAL;
	}
	if (bpf_map_lookup_elem(&cookie_pid_map, &cookie)) {
		// Cookie to pid mapping already exists.
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
