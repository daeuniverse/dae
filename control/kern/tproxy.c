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
	__uint(max_entries, 65536);
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

struct egress_return_handoff_entry {
	__u32 ifindex;
	__u8 smac[6];
	__u8 dmac[6];
	__u8 from_wan;
	__u8 padding[3];
	__u64 last_seen_ns;
};

struct dae_param {
	__u32 tproxy_port;
	__u32 control_plane_pid;
	__u32 dae0_ifindex;
	__u32 dae_netns_id;
	__u8 dae0peer_mac[6];
	__u8 padding_after_mac[2]; // pad to align use_redirect_peer
	__u8 use_redirect_peer;
	__u8 padding1;
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct tuples_key);
	__type(value, struct egress_return_handoff_entry);
	__uint(max_entries, 65536);
} egress_return_handoff_map SEC(".maps");

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
	__uint(max_entries, MAX_MATCH_SET_LEN);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} routing_map SEC(".maps");

// key=0: active routing rules length in routing_map.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} routing_meta_map SEC(".maps");

struct domain_routing {
	__u32 bitmap[MAX_MATCH_SET_LEN / 32];
};

// domain_routing_map: domain → routing bitmap cache (HASH, no LRU).
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

// udp_conn_state: connection state with embedded routing for consistency.
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

// tcp_conn_state: connection state with embedded routing for consistency.
struct tcp_conn_state {
	// For each flow (echo symmetric path), note the original flow direction.
	// Mark as true if traffic go through wan ingress.
	bool is_wan_ingress_direction;

	// Connection state: 0 = active, 1 = closing (FIN/RST seen)
	// When in closing state, userspace cleanup will remove this entry.
	__u8 state;

	// Last seen timestamp in nanoseconds (bpf_ktime_get_ns()).
	// Userspace cleanup periodically removes expired entries.
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

// key=0: UDP conn overflow count; key=1: TCP conn overflow count.
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

// Events delivered to userspace via ring buffer.
enum dae_event_type {
	DAE_EVENT_BLOCKED = 0,       // Connection blocked (OUTBOUND_BLOCK)
	DAE_EVENT_UDP_CONN_OVERFLOW = 1, // UDP conn state map overflow
	DAE_EVENT_TCP_CONN_OVERFLOW = 2, // TCP conn state map overflow
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

	// Both iph and ipv6h are stack-allocated; check version field.
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
		if (iph_ptr->ihl < 5)
			return -EFAULT;

		// Copy saddr/daddr early so get_tuples() works for PARSE_FRAGMENT.
		iph->version = iph_ptr->version;
		iph->ihl = iph_ptr->ihl;
		iph->protocol = iph_ptr->protocol;
		iph->saddr = iph_ptr->saddr;
		iph->daddr = iph_ptr->daddr;
		*ihl = iph_ptr->ihl;
		*l4proto = iph_ptr->protocol;

		__u32 ip_hdr_len = iph_ptr->ihl * 4;
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

		// First fragment carries L4; non-initial falls back.
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

			ret = bpf_skb_load_bytes(skb, offset, &nexthdr, 1);
			if (ret)
				return -EFAULT;

			__u8 hdr_ext_len = 0;

			ret = bpf_skb_load_bytes(skb, offset + 1, &hdr_ext_len,
						 sizeof(hdr_ext_len));
			if (ret)
				return -EFAULT;

			__u32 ext_len = ipv6_optlen(hdr_ext_len);

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
			return 1;
		}
		return 0;
	}

	return 1;
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
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct parsed_packet);
	__uint(max_entries, 1);
} pkt_scratch_map SEC(".maps");

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
	if (ctx->l4proto == IPPROTO_ICMPV6)
		return 1;

	// PARSE_FRAGMENT still populates the IP tuple for callers.
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

	if (!(ctx->route_state &
	      (ROUTE_STATE_BAD_RULE | ROUTE_STATE_GOOD_SUBRULE))) {
		if (route_eval_match(ctx, match_set, k, l4proto_type,
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
	// bpf_redirect_peer requires kernel >= 6.8 (CVE-2025-37959 fix).
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

static __always_inline bool
wan_egress_needs_control_plane(__u8 outbound, __u32 mark)
{
	return !(outbound == OUTBOUND_DIRECT && mark == 0);
}

static __always_inline void
fill_routing_result(struct routing_result *dst,
		    __u32 mark, __u8 must, __u8 outbound,
		    const __u8 mac[6], __u8 dscp,
		    const char *pname, __u32 pid)
{
	__builtin_memset(dst, 0, sizeof(*dst));
	dst->mark = mark;
	dst->must = must;
	dst->outbound = outbound;
	dst->pid = pid;
	dst->dscp = dscp;
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

static __always_inline int
publish_redirect_track_for_packet(struct __sk_buff *skb, __u32 link_h_len,
				  const struct tuples *tuples,
				  const struct ethhdr *ethh, __u8 from_wan)
{
	struct redirect_tuple redirect_tuple = {};
	struct redirect_entry redirect_entry = {};
	long map_ret;

	fill_redirect_tuple_from_forward_packet(skb, tuples, &redirect_tuple);
	fill_redirect_entry_from_forward_packet(skb->ifindex, link_h_len, ethh,
						from_wan, &redirect_entry);

	map_ret = bpf_map_update_elem(&redirect_track, &redirect_tuple,
				      &redirect_entry, BPF_ANY);
	if (map_ret) {
		bpf_printk("redirect_track update failed: %d", (int)map_ret);
		return (int)map_ret;
	}
	return 0;
}

static __always_inline int
publish_egress_return_handoff(struct __sk_buff *skb, __u32 link_h_len,
			      const struct tuples_key *tuples,
			      const struct ethhdr *ethh, __u8 from_wan)
{
	struct egress_return_handoff_entry entry = {};
	long ret;

	entry.ifindex = skb->ifindex;
	entry.from_wan = from_wan;
	entry.last_seen_ns = bpf_ktime_get_ns();
	if (link_h_len == ETH_HLEN && ethh) {
		__builtin_memcpy(entry.smac, ethh->h_source, 6);
		__builtin_memcpy(entry.dmac, ethh->h_dest, 6);
	}
	ret = bpf_map_update_elem(&egress_return_handoff_map, tuples, &entry,
				  BPF_ANY);
	if (ret)
		bpf_printk("egress_return_handoff update failed: %d", (int)ret);
	return (int)ret;
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

static __always_inline bool
udp_wan_egress_handoff_mandatory(const struct tuples *tuples,
				 const struct udp_conn_state *udp_conn_state)
{
	return is_short_lived_udp_traffic((struct tuples_key *)&tuples->five) ||
	       !udp_conn_state;
}

// mark_udp_seen: update/create UDP conn state with optional routing metadata.
// Expired entries are pruned on lookup. Map overflow increments bpf_stats_map.
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

// mark_tcp_seen: update/create TCP conn state with optional routing metadata.
// SYN starts new lifecycle; FIN/RST transitions to CLOSING.
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

// Reverse-direction conntrack refresh for LAN egress.
static __noinline int do_tproxy_lan_egress(struct __sk_buff *skb, __u32 link_h_len)
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
		if (ctx->udph.source == bpf_htons(53) || ctx->udph.dest == bpf_htons(53))
			return TC_ACT_PIPE;

		struct tuples tuples;
		struct tuples_key reversed_tuples_key;

		get_tuples(skb, &tuples, &ctx->iph, &ctx->ipv6h,
			   &ctx->tcph, &ctx->udph, ctx->l4proto);
		copy_reversed_tuples(&tuples.five, &reversed_tuples_key);
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
				     struct parsed_packet *pkt,
				     __u64 routing_meta_raw)
{
	union routing_meta routing_meta = {
		.raw = routing_meta_raw,
	};
	struct routing_handoff_entry handoff = {};

	if (prep_redirect_to_control_plane(skb, link_h_len, &pkt->tuples,
					   &pkt->ethh, 0)) {
		return TC_ACT_SHOT;
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
		struct tcp_conn_state *tcp_state;

		// Track TCP connection state; reuse returned pointer.
		tcp_state = mark_tcp_seen(&pkt->tuples.five, &pkt->tcph, false,
					  NULL, NULL, NULL, NULL,
					  0, NULL, 0);
		// No cached state for an established packet: keep the historical
		// passthrough behavior instead of recomputing routing.
		if (!tcp_state)
			return TC_ACT_OK;

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

	// Socket lookup before routing to detect local services (NAT loopback).
	// TCP: only LISTEN sockets; skip SYN for CF back-to-source compat.
	// UDP: any matching socket indicates local service.
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
			if (!(pkt->tcph.syn && !pkt->tcph.ack)) {
				sk = bpf_skc_lookup_tcp(skb, &tuple, tuple_size,
							PARAM.dae_netns_id, 0);
				if (sk) {
					if (!bpf_sock_is_dae_socket(sk) &&
					    sk->state == BPF_TCP_LISTEN) {
						bpf_sk_release(sk);
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
						bpf_printk("tcp(lan): local LISTEN socket found, pass through");
#endif
						return TC_ACT_OK;
					}
					bpf_sk_release(sk);
				}
			}
		} else {
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

	// Cache routing in conn state (skip DNS to avoid map churn).
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

static __noinline int do_tproxy_wan_ingress(struct __sk_buff *skb, __u32 link_h_len)
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

	// Reverse-direction conntrack refresh.
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
		if (ctx->udph.source == bpf_htons(53) || ctx->udph.dest == bpf_htons(53))
			return TC_ACT_PIPE;

		struct tuples tuples;
		struct tuples_key reversed_tuples_key;

		get_tuples(skb, &tuples, &ctx->iph, &ctx->ipv6h,
			   &ctx->tcph, &ctx->udph, ctx->l4proto);
		copy_reversed_tuples(&tuples.five, &reversed_tuples_key);
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
		// Established TCP: only proxied connections have cached state.
		struct tcp_conn_state *tcp_conn = mark_tcp_seen(
			&tuples->five, tcph, false,
			NULL, NULL, NULL, NULL,
			0, NULL, 0);

		if (!tcp_conn || !tcp_conn->meta.data.has_routing)
			return TC_ACT_OK;

		outbound = tcp_conn->meta.data.outbound;
		mark = tcp_conn->meta.data.mark;
		must = tcp_conn->meta.data.must;
		__builtin_memcpy(handoff_mac, tcp_conn->mac, 6);
		__builtin_memcpy(scratch->mac, tcp_conn->mac, 6);
		handoff_pname = (const char *)tcp_conn->pname;
		handoff_pid = tcp_conn->pid;
	}

	if (!wan_egress_needs_control_plane(outbound, mark)) {
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

	struct routing_result routing_result = {};

	fill_routing_result(&routing_result, mark, must, outbound, handoff_mac,
			    tuples->dscp, handoff_pname, handoff_pid);
	/* TCP has embedded conn-state routing metadata; handoff is best-effort. */
	publish_routing_handoff(&tuples->five, &routing_result);

	if (publish_egress_return_handoff(skb, link_h_len, &tuples->five,
					  ethh, 1))
		return TC_ACT_SHOT;

	if (rewrite_packet_for_control_plane(skb, link_h_len, 1))
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

	if (!wan_egress_needs_control_plane(outbound, mark))
		return TC_ACT_OK;
	else if (unlikely(outbound == OUTBOUND_BLOCK))
		return TC_ACT_SHOT;

	if (!wan_outbound_is_alive(skb, outbound, IPPROTO_UDP,
				   tuples->five.dport))
		return TC_ACT_SHOT;

	struct routing_result routing_result = {};
	bool handoff_mandatory = udp_wan_egress_handoff_mandatory(tuples,
							      udp_conn_state);

	fill_routing_result(&routing_result, mark, must, outbound, mac,
			    tuples->dscp, handoff_pname, handoff_pid);
	if (publish_routing_handoff(&tuples->five, &routing_result) &&
	    handoff_mandatory)
		return TC_ACT_SHOT;

	if (publish_egress_return_handoff(skb, link_h_len, &tuples->five,
					  ethh, 1))
		return TC_ACT_SHOT;

	if (rewrite_packet_for_control_plane(skb, link_h_len, 1))
		return TC_ACT_SHOT;
	skb->cb[0] = TPROXY_MARK;
	skb->cb[1] = IPPROTO_UDP;
	return redirect_to_control_plane_egress();
}

// Per-CPU scratch to stay under 512-byte stack limit across the call chain.
static __noinline int do_tproxy_wan_egress(struct __sk_buff *skb, __u32 link_h_len)
{
	if (skb->ingress_ifindex != NOWHERE_IFINDEX)
		return TC_ACT_OK;

	__u32 scratch_key = 0;
	struct parsed_packet *pkt =
		bpf_map_lookup_elem(&pkt_scratch_map, &scratch_key);

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
	struct redirect_tuple redirect_tuple = {};
	int ret;

	ret = load_redirect_tuple(skb, &redirect_tuple);
	if (ret)
		return TC_ACT_OK;
	struct redirect_entry *redirect_entry =
		bpf_map_lookup_elem(&redirect_track, &redirect_tuple);

	if (!redirect_entry)
		return TC_ACT_OK;

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

/* Get pid and command name from current task. */
static __always_inline int get_pid_pname(struct pid_pname *pid_pname)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	pid_pname->last_seen_ns = bpf_ktime_get_ns();
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
