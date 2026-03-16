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
#include "headers/bpf_timer.h"
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
#define IPV6_MAX_EXTENSIONS 8

#define ipv6_optlen(p) (((p)+1) << 3)

#define TPROXY_MARK 0x8000000

// UDP timeout constants
#define TIMEOUT_UDP_DNS    17e9 /* 17s */
#define TIMEOUT_UDP_NORMAL 6e10 /* 60s */

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
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
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
	__u32 control_plane_pid;
	__u32 dae0_ifindex;
	__u8 dae0peer_mac[6];
	__u8 padding[2];
};

#define DAE_TC_PASS 0
#define DAE_TC_DROP 2
// TCX uses -1 for next, TC uses 3 (TC_ACT_PIPE). We use PIPE here
// which works for both TCX and TC (TCX treats 3 as continue to next).
#define DAE_TC_NEXT 3

/* Use const volatile for cilium/ebpf v0.20.0 compatibility.
 * This ensures the variable is placed in .rodata section and
 * can be rewritten from userspace via RewriteConstants. */
const volatile struct dae_param PARAM = {};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct tuples_key);
	__type(value, struct routing_result); // outbound
	__uint(max_entries, MAX_DST_MAPPING_NUM);
	/// NOTICE: It MUST be pinned.
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} routing_tuples_map SEC(".maps");

/* Sockets in fast_sock map are used for fast-redirecting via
 * sk_skb/stream_verdict. Sockets are automactically deleted from map once
 * closed, so we don't need to worry about stale entries.
 */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct tuples_key);
	__type(value, __u64);
	__uint(max_entries, 65535);
} fast_sock SEC(".maps");

/* LPM key structure matching kernel's bpf_lpm_trie_key format.
 * The trie_key contains the prefixlen field, and data[4] provides
 * the flexible array storage for IPv6 addresses in network byte order.
 * This matches the structure layout used successfully in commit 2cd6118.
 */
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

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __be32[4]);
	__type(value, struct domain_routing);
	__uint(max_entries, MAX_DOMAIN_ROUTING_NUM);
	/// NOTICE: No persistence.
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} domain_routing_map SEC(".maps");

// LPM cache for accelerating IpSet/SourceIpSet/Mac lookups
// Key: (match_set_index, IP address)
// Value: 1 if the IP matches the LPM trie, 0 otherwise
// NOTE: match_set_index is globally unique among LPM-backed match sets.
struct lpm_cache_key {
	__u32 match_set_index;
	__u32 ip[4];  // IPv6 address (IPv4 uses last 32 bits)
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct lpm_cache_key);
	__type(value, __u8);  // 1 = match, 0 = no match
	__uint(max_entries, 65536);
} lpm_cache_map SEC(".maps");

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
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, struct pid_pname);
	__uint(max_entries, MAX_COOKIE_PID_PNAME_MAPPING_NUM);
	/// NOTICE: No persistence.
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cookie_pid_map SEC(".maps");

struct udp_conn_state {
	// For each flow (echo symmetric path), note the original flow direction.
	// Mark as true if traffic go through wan ingress.
	// For traffic from lan that go through wan ingress, dae parse them in lan egress
	bool is_wan_ingress_direction;

	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DST_MAPPING_NUM);
	__type(key, struct tuples_key);
	__type(value, struct udp_conn_state);
} udp_conn_state_map SEC(".maps");

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

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		tuples->five.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuples->five.sip.u6_addr32[3] = iph->saddr;

		tuples->five.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuples->five.dip.u6_addr32[3] = iph->daddr;

		tuples->dscp = ipv4_get_dscp(iph);

	} else {
		__builtin_memcpy(&tuples->five.dip, &ipv6h->daddr,
				 IPV6_BYTE_LENGTH);
		__builtin_memcpy(&tuples->five.sip, &ipv6h->saddr,
				 IPV6_BYTE_LENGTH);

		tuples->dscp = ipv6_get_dscp(ipv6h);
	}
	if (l4proto == IPPROTO_TCP) {
		tuples->five.sport = tcph->source;
		tuples->five.dport = tcph->dest;
	} else {
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

struct ipv6_ext_ctx {
	const struct __sk_buff *skb;
	__u32 *offset;
	__u8 *nexthdr;
	int result;
};

static __noinline int ipv6_ext_skip_loop_cb(__u32 index, void *data)
{
	(void)index;  // Unused parameter required by bpf_loop callback
	struct ipv6_ext_ctx *ctx = data;

	if (*ctx->nexthdr == IPPROTO_NONE)
		return 1;

	if (!is_extension_header(*ctx->nexthdr))
		return 1;

	int ret = bpf_skb_load_bytes(ctx->skb, *ctx->offset, ctx->nexthdr,
					 sizeof(*ctx->nexthdr));
	if (ret) {
		bpf_printk("not a valid IPv6 packet");
		ctx->result = -EFAULT;
		return 1;
	}

	__u8 hdr_ext_len = 0;

	ret = bpf_skb_load_bytes(ctx->skb, *ctx->offset + 1, &hdr_ext_len,
				 sizeof(hdr_ext_len));
	if (ret) {
		bpf_printk("not a valid IPv6 packet");
		ctx->result = -EFAULT;
		return 1;
	}

	*ctx->offset += ipv6_optlen(hdr_ext_len);
	return 0;
}

// parse_transport_fast returns this code when it cannot safely parse via
// direct packet access and should fall back to parse_transport_slow.
#define PARSE_TRANSPORT_FALLBACK 2

static __always_inline int
parse_transport_fast(const struct __sk_buff *skb, __u32 link_h_len,
		     struct ethhdr *ethh, struct iphdr *iph,
		     struct ipv6hdr *ipv6h, struct icmp6hdr *icmp6h,
		     struct tcphdr *tcph, struct udphdr *udph, __u8 *ihl,
		     __u8 *l4proto)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 offset = 0;

	*ihl = 0;
	*l4proto = 0;
	__builtin_memset(iph, 0, sizeof(struct iphdr));
	__builtin_memset(ipv6h, 0, sizeof(struct ipv6hdr));
	__builtin_memset(icmp6h, 0, sizeof(struct icmp6hdr));
	__builtin_memset(tcph, 0, sizeof(struct tcphdr));
	__builtin_memset(udph, 0, sizeof(struct udphdr));

	if (link_h_len == ETH_HLEN) {
		struct ethhdr *eth_ptr = data;

		if ((void *)(eth_ptr + 1) > data_end)
			return PARSE_TRANSPORT_FALLBACK;
		__builtin_memcpy(ethh, eth_ptr, sizeof(*ethh));
		offset += sizeof(struct ethhdr);
	} else {
		__builtin_memset(ethh, 0, sizeof(struct ethhdr));
		ethh->h_proto = skb->protocol;
	}

	if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph_ptr = data + offset;
		__u32 l4_offset;

		if ((void *)(iph_ptr + 1) > data_end)
			return PARSE_TRANSPORT_FALLBACK;
		if (iph_ptr->ihl < 5)
			return PARSE_TRANSPORT_FALLBACK;

		l4_offset = offset + iph_ptr->ihl * 4;
		if (data + l4_offset > data_end)
			return PARSE_TRANSPORT_FALLBACK;

		__builtin_memcpy(iph, iph_ptr, sizeof(*iph));
		*ihl = iph->ihl;
		*l4proto = iph->protocol;

		switch (iph->protocol) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph_ptr = data + l4_offset;

			if ((void *)(tcph_ptr + 1) > data_end)
				return PARSE_TRANSPORT_FALLBACK;
			__builtin_memcpy(tcph, tcph_ptr, sizeof(*tcph));
			return 0;
		}
		case IPPROTO_UDP: {
			struct udphdr *udph_ptr = data + l4_offset;

			if ((void *)(udph_ptr + 1) > data_end)
				return PARSE_TRANSPORT_FALLBACK;
			__builtin_memcpy(udph, udph_ptr, sizeof(*udph));
			return 0;
		}
		default:
			return 1;
		}
	} else if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6h_ptr = data + offset;

		if ((void *)(ipv6h_ptr + 1) > data_end)
			return PARSE_TRANSPORT_FALLBACK;
		__builtin_memcpy(ipv6h, ipv6h_ptr, sizeof(*ipv6h));

		offset += sizeof(struct ipv6hdr);
		*ihl = sizeof(struct ipv6hdr) / 4;
		*l4proto = ipv6h->nexthdr;

		// Extension headers are parsed by the slow path.
		if (is_extension_header(*l4proto))
			return PARSE_TRANSPORT_FALLBACK;

		switch (*l4proto) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph_ptr = data + offset;

			if ((void *)(tcph_ptr + 1) > data_end)
				return PARSE_TRANSPORT_FALLBACK;
			__builtin_memcpy(tcph, tcph_ptr, sizeof(*tcph));
			return 0;
		}
		case IPPROTO_UDP: {
			struct udphdr *udph_ptr = data + offset;

			if ((void *)(udph_ptr + 1) > data_end)
				return PARSE_TRANSPORT_FALLBACK;
			__builtin_memcpy(udph, udph_ptr, sizeof(*udph));
			return 0;
		}
		case IPPROTO_ICMPV6: {
			struct icmp6hdr *icmp6h_ptr = data + offset;

			if ((void *)(icmp6h_ptr + 1) > data_end)
				return PARSE_TRANSPORT_FALLBACK;
			__builtin_memcpy(icmp6h, icmp6h_ptr, sizeof(*icmp6h));
			return 0;
		}
		default:
			return 1;
		}
	}
	return 1;
}

static __always_inline int
parse_transport_slow(const struct __sk_buff *skb, __u32 link_h_len,
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
		if (ret) {
			bpf_printk("not ethernet packet");
			return 1;
		}
		// Skip ethhdr for next hdr.
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

	// bpf_printk("parse_transport: h_proto: %u ? %u %u", ethh->h_proto,
	//						bpf_htons(ETH_P_IP),
	// bpf_htons(ETH_P_IPV6));
	if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
		ret = bpf_skb_load_bytes(skb, offset, iph,
					 sizeof(struct iphdr));
		if (ret)
			return -EFAULT;
		if (iph->ihl < 5)
			return -EFAULT;
		// Skip ipv4hdr and options for next hdr.
		offset += iph->ihl * 4;

		// We only process TCP and UDP traffic.
		*l4proto = iph->protocol;
		switch (iph->protocol) {
		case IPPROTO_TCP:
			ret = bpf_skb_load_bytes(skb, offset, tcph,
						 sizeof(struct tcphdr));
			if (ret) {
				// Not a complete tcphdr.
				return -EFAULT;
			}
			break;
		case IPPROTO_UDP:
			ret = bpf_skb_load_bytes(skb, offset, udph,
						 sizeof(struct udphdr));
			if (ret) {
				// Not a complete udphdr.
				return -EFAULT;
			}
			break;
		default:
			return 1;
		}
		*ihl = iph->ihl;
		return 0;
	} else if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
		ret = bpf_skb_load_bytes(skb, offset, ipv6h,
					 sizeof(struct ipv6hdr));
		if (ret) {
			bpf_printk("not a valid IPv6 packet");
			return -EFAULT;
		}

		offset += sizeof(struct ipv6hdr);
		*ihl = sizeof(struct ipv6hdr) / 4;
		__u8 nexthdr = ipv6h->nexthdr;

		// Skip all extension headers.
		struct ipv6_ext_ctx ext_ctx = {
			.skb = skb,
			.offset = &offset,
			.nexthdr = &nexthdr,
			.result = 0
		};

		ret = bpf_loop(IPV6_MAX_EXTENSIONS, ipv6_ext_skip_loop_cb, &ext_ctx, 0);
		if (ret < 0)
			return ret;
		if (ext_ctx.result)
			return ext_ctx.result;

		if (is_extension_header(nexthdr)) {
			bpf_printk("Unexpected hdr or exceeds IPV6_MAX_EXTENSIONS limit");
			return 1;
		}

		*l4proto = nexthdr;

		switch (nexthdr) {
		case IPPROTO_TCP:
			ret = bpf_skb_load_bytes(skb, offset, tcph,
						 sizeof(struct tcphdr));
			if (ret) {
				// Not a complete tcphdr.
				return -EFAULT;
			}
			break;
		case IPPROTO_UDP:
			ret = bpf_skb_load_bytes(skb, offset, udph,
						 sizeof(struct udphdr));
			if (ret) {
				// Not a complete udphdr.
				return -EFAULT;
			}
			break;
		case IPPROTO_ICMPV6:
			ret = bpf_skb_load_bytes(skb, offset, icmp6h,
						 sizeof(struct icmp6hdr));
			if (ret) {
				// Not a complete icmp6hdr.
				return -EFAULT;
			}
			break;
		default:
			/// EXPECTED: Maybe ICMP, MPLS, etc.
			// bpf_printk("IP but not supported packet: protocol is %u",
			// iph->protocol);
			return 1;
		}
		return 0;
	}
	// bpf_printk("unknown link proto: %u", bpf_ntohl(ethh->h_proto));
	return 1;
}

static __always_inline int
parse_transport(const struct __sk_buff *skb, __u32 link_h_len,
		struct ethhdr *ethh, struct iphdr *iph, struct ipv6hdr *ipv6h,
		struct icmp6hdr *icmp6h, struct tcphdr *tcph,
		struct udphdr *udph, __u8 *ihl, __u8 *l4proto)
{
	int ret = parse_transport_fast(skb, link_h_len, ethh, iph, ipv6h, icmp6h,
				       tcph, udph, ihl, l4proto);

	if (ret == PARSE_TRANSPORT_FALLBACK)
		return parse_transport_slow(skb, link_h_len, ethh, iph, ipv6h,
					    icmp6h, tcph, udph, ihl, l4proto);
	return ret;
}

struct route_params {
	__u32 flag[8];
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

// Pack MAC address (6 bytes) into u32 array for route_params.mac
// Reduces code duplication and improves instruction cache utilization
static __always_inline void pack_mac_to_u32_array(__u32 *mac_array, const __u8 *mac)
{
	mac_array[2] = bpf_htonl((mac[0] << 8) | mac[1]);
	mac_array[3] = bpf_htonl((mac[2] << 24) | (mac[3] << 16) |
				 (mac[4] << 8) | mac[5]);
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

#ifndef __BPF_TEST_DISABLE_LPM_CACHE
	// Build cache key.
	// lpm_key->data is __be32[4], directly copy to cache_key.ip
	struct lpm_cache_key cache_key = {
		.match_set_index = match_set->index,
		.ip = { lpm_key->data[0], lpm_key->data[1], lpm_key->data[2],
			lpm_key->data[3] }
	};

	// Try LPM cache first for better performance (10x faster)
	__u8 *cached = bpf_map_lookup_elem(&lpm_cache_map, &cache_key);

	if (cached) {
		// Cache hit: use cached result
		if (*cached)
			mark_matched(ctx);
		return 0;
	}
#endif
	// Cache miss or test mode: perform LPM lookup
	lpm = bpf_map_lookup_elem(&lpm_array_map, &match_set->index);
	if (unlikely(!lpm)) {
		ctx->result = -EFAULT;
		return 1;
	}

	// Perform LPM lookup and check result
#ifndef __BPF_TEST_DISABLE_LPM_CACHE
	__u8 lpm_match = 0;
#endif

	if (bpf_map_lookup_elem(lpm, lpm_key)) {
		// match_set hits.
		mark_matched(ctx);
#ifndef __BPF_TEST_DISABLE_LPM_CACHE
		lpm_match = 1;
#endif
	}
#ifndef __BPF_TEST_DISABLE_LPM_CACHE
	// Update cache with lookup result
	bpf_map_update_elem(&lpm_cache_map, &cache_key, &lpm_match, BPF_ANY);
#endif
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
	__u8 is_wan = ctx->params->flag[2];
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
#define _is_wan params->flag[2]
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
		(ctx.h_dport == 53 && _l4proto_type == L4ProtoType_UDP)
		? ROUTE_STATE_DNS_QUERY
		: 0;

	// Initialize LPM keys directly (eliminates temporary stack variables)
	ctx.lpm_key_saddr.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
	ctx.lpm_key_daddr.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
	ctx.lpm_key_mac.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
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

static __always_inline void prep_redirect_to_control_plane(
	struct __sk_buff *skb, __u32 link_h_len, struct tuples *tuples,
	__u8 l4proto, struct ethhdr *ethh, __u8 from_wan, struct tcphdr *tcph)
{
	/* Redirect from L3 dev to L2 dev, e.g. wg/ipip/ppp/tun -> veth */
	if (!link_h_len) {
		__u16 l3proto = skb->protocol;

		bpf_skb_change_head(skb, sizeof(struct ethhdr), 0);
		bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
				    &l3proto, sizeof(l3proto), 0);
	}

	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
			    (void *)&PARAM.dae0peer_mac, sizeof(ethh->h_dest),
			    0);

	struct redirect_tuple redirect_tuple = {};

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		redirect_tuple.sip.u6_addr32[3] = tuples->five.sip.u6_addr32[3];
		redirect_tuple.dip.u6_addr32[3] = tuples->five.dip.u6_addr32[3];
	} else {
		__builtin_memcpy(&redirect_tuple.sip, &tuples->five.sip,
				 IPV6_BYTE_LENGTH);
		__builtin_memcpy(&redirect_tuple.dip, &tuples->five.dip,
				 IPV6_BYTE_LENGTH);
	}
	struct redirect_entry redirect_entry = {};

	redirect_entry.ifindex = skb->ifindex;
	redirect_entry.from_wan = from_wan;
	__builtin_memcpy(redirect_entry.smac, ethh->h_source,
			 sizeof(ethh->h_source));
	__builtin_memcpy(redirect_entry.dmac, ethh->h_dest,
			 sizeof(ethh->h_dest));
	bpf_map_update_elem(&redirect_track, &redirect_tuple, &redirect_entry,
			    BPF_ANY);

	skb->cb[0] = TPROXY_MARK;
	skb->cb[1] = 0;
	if ((l4proto == IPPROTO_TCP && tcph->syn) || l4proto == IPPROTO_UDP)
		skb->cb[1] = l4proto;
}

static int refresh_udp_conn_state_timer_cb(void *_udp_conn_state_map,
					   struct tuples_key *key,
					   struct udp_conn_state *val)
{
	(void)_udp_conn_state_map;  // Unused parameter (map is implicit)
	(void)val;                   // Unused parameter (we only need the key)
	bpf_map_delete_elem(&udp_conn_state_map, key);
	return 0;
}

static __always_inline void copy_reversed_tuples(struct tuples_key *key,
						 struct tuples_key *dst)
{
	// memset is required: struct has 3 bytes of padding that must be zero
	// for consistent map key comparisons (memcmp checks entire struct)
	__builtin_memset(dst, 0, sizeof(*dst));
	dst->l4proto = key->l4proto;
	dst->sip = key->dip;
	dst->dip = key->sip;
	dst->sport = key->dport;
	dst->dport = key->sport;
}

static __always_inline bool
get_fast_redirect_key(const struct __sk_buff *skb, struct tuples_key *key)
{
	__builtin_memset(key, 0, sizeof(*key));
	key->l4proto = IPPROTO_TCP;

	/* IPv4-only fast path for sk_skb/stream_verdict compatibility.
	 * IPv6 requires direct ctx access which verifier may reject.
	 * IPv6 connections will use userspace relay instead. */
	if (skb->family != AF_INET)
		return false;

	key->sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key->sip.u6_addr32[3] = skb->remote_ip4;
	key->dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key->dip.u6_addr32[3] = skb->local_ip4;
	key->sport = skb->remote_port >> 16;
	key->dport = bpf_htons((__u16)skb->local_port);
	return true;
}

// DNS queries/replies are short-lived; skipping conntrack/cache for them
// reduces unnecessary UDP state churn.
static __always_inline bool is_short_lived_udp_traffic(struct tuples_key *key)
{
	return key->l4proto == IPPROTO_UDP &&
	       (key->dport == bpf_htons(53) || key->sport == bpf_htons(53));
}

static __always_inline struct udp_conn_state *
refresh_udp_conn_state_timer(struct tuples_key *key, bool is_wan_ingress_direction)
{
	struct udp_conn_state *state = bpf_map_lookup_elem(&udp_conn_state_map, key);
	__u64 timeout;

	if (state)
		goto rearm;

	struct udp_conn_state new_state = {};

	new_state.is_wan_ingress_direction = is_wan_ingress_direction;
	if (unlikely(bpf_map_update_elem(&udp_conn_state_map, key, &new_state, BPF_NOEXIST)))
		return NULL;

	state = bpf_map_lookup_elem(&udp_conn_state_map, key);
	if (unlikely(!state))
		return NULL;

	// Initialize timer with error handling
	int ret = bpf_timer_init(&state->timer, &udp_conn_state_map, CLOCK_MONOTONIC);

	if (ret != 0) {
		// Timer init failed, delete entry to prevent leak
		bpf_map_delete_elem(&udp_conn_state_map, key);
		return NULL;
	}

	ret = bpf_timer_set_callback(&state->timer, refresh_udp_conn_state_timer_cb);
	if (ret != 0) {
		bpf_map_delete_elem(&udp_conn_state_map, key);
		return NULL;
	}

rearm:
	if (is_short_lived_udp_traffic(key))
		timeout = TIMEOUT_UDP_DNS;
	else
		timeout = TIMEOUT_UDP_NORMAL;
	ret = bpf_timer_start(&state->timer, timeout, 0);
	if (ret != 0) {
		// Timer start failed, delete entry
		bpf_map_delete_elem(&udp_conn_state_map, key);
		return NULL;
	}

	return state;
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

static __always_inline int do_tproxy_lan_egress(struct __sk_buff *skb, u32 link_h_len)
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
		return DAE_TC_NEXT;
	}

	if (skb->ingress_ifindex == NOWHERE_IFINDEX && // Only drop NDP_REDIRECT packets from localhost
	    l4proto == IPPROTO_ICMPV6 && icmp6h.icmp6_type == NDP_REDIRECT) {
		// REDIRECT (NDP)
		return DAE_TC_DROP;
	}

	// Update UDP Conntrack
	if (l4proto == IPPROTO_UDP) {
		// DNS traffic is short-lived and stateless in our fast path.
		// Skip tuple build + conntrack update to reduce state churn.
		if (udph.source == bpf_htons(53) || udph.dest == bpf_htons(53))
			return DAE_TC_NEXT;

		struct tuples tuples;
		struct tuples_key reversed_tuples_key;

		get_tuples(skb, &tuples, &iph, &ipv6h, &tcph, &udph, l4proto);
		copy_reversed_tuples(&tuples.five, &reversed_tuples_key);
		if (!refresh_udp_conn_state_timer(&reversed_tuples_key, true))
			return DAE_TC_DROP;
	}

	return DAE_TC_NEXT;
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

static __noinline bool
wan_outbound_is_alive(struct __sk_buff *skb, __u8 outbound, __u8 l4proto,
		      __be16 dport);

static __always_inline int do_tproxy_lan_ingress(struct __sk_buff *skb, u32 link_h_len)
{
	__u32 scratch_key = 0;
	struct lan_ingress_parsed *pkt =
		bpf_map_lookup_elem(&lan_ingress_scratch_map, &scratch_key);

	if (unlikely(!pkt))
		return DAE_TC_DROP;

	/* Ensure scratch bytes are initialized even if verifier can't precisely
	 * track writes done through callee pointer arguments. */
	__builtin_memset(pkt, 0, sizeof(*pkt));
	int ret = parse_lan_ingress_packet(skb, link_h_len, pkt);

	if (ret) {
		if (ret < 0)
			bpf_printk("parse_transport: %d", ret);
		return DAE_TC_PASS;
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
			return DAE_TC_PASS;
		}

		skb->mark = mark;
		if (outbound == OUTBOUND_DIRECT)
			return DAE_TC_PASS;
		if (unlikely(outbound == OUTBOUND_BLOCK))
			return DAE_TC_DROP;
		if (!wan_outbound_is_alive(skb, outbound, pkt->l4proto,
					   pkt->tuples.five.dport))
			return DAE_TC_DROP;
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
				refresh_udp_conn_state_timer(&pkt->tuples.five, false);
			if (!conn_state)
				return DAE_TC_DROP;
			if (conn_state->is_wan_ingress_direction) {
				// Replay (outbound) of an inbound flow
				// => direct.
				return DAE_TC_PASS;
			}
		}
		params.l4hdr = &pkt->udph;
		params.flag[0] = L4ProtoType_UDP;
	}
	if (skb->protocol == bpf_htons(ETH_P_IP))
		params.flag[1] = IpVersionType_4;
	else
		params.flag[1] = IpVersionType_6;
	params.flag[6] = pkt->tuples.dscp;
	pack_mac_to_u32_array(params.mac, pkt->ethh.h_source);
	params.saddr = pkt->tuples.five.sip.u6_addr32;
	params.daddr = pkt->tuples.five.dip.u6_addr32;
	__s64 s64_ret;

	s64_ret = route(&params);
	if (s64_ret < 0) {
		bpf_printk("shot routing: %d", s64_ret);
		return DAE_TC_DROP;
	}
	struct routing_result routing_result = { 0 };

	routing_result.outbound = s64_ret;
	routing_result.mark = s64_ret >> 8;
	routing_result.must = (s64_ret >> 40) & 1;
	routing_result.dscp = pkt->tuples.dscp;
	__builtin_memcpy(routing_result.mac, pkt->ethh.h_source,
			 sizeof(routing_result.mac));
	/// NOTICE: No pid pname info for LAN packet (traffic is forwarded, not locally originated).

	// Save routing result.
	if (pkt->l4proto == IPPROTO_UDP &&
	    is_short_lived_udp_traffic(&pkt->tuples.five)) {
		// Skip cache for short-lived DNS to avoid map churn.
	} else {
		ret = bpf_map_update_elem(&routing_tuples_map, &pkt->tuples.five,
					  &routing_result, BPF_ANY);
		if (ret) {
			bpf_printk("shot save routing result: %d", ret);
			return DAE_TC_DROP;
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
	prep_redirect_to_control_plane(skb, link_h_len, &pkt->tuples, pkt->l4proto,
				       &pkt->ethh, 0, &pkt->tcph);
	return bpf_redirect(PARAM.dae0_ifindex, 0);

direct:
	return DAE_TC_PASS;

block:
	return DAE_TC_DROP;
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

static __always_inline int do_tproxy_wan_ingress(struct __sk_buff *skb, u32 link_h_len)
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
		return DAE_TC_NEXT;
	}

	// Update UDP Conntrack
	if (l4proto == IPPROTO_UDP) {
		// DNS traffic is short-lived and stateless in our fast path.
		// Skip tuple build + conntrack update to reduce state churn.
		if (udph.source == bpf_htons(53) || udph.dest == bpf_htons(53))
			return DAE_TC_NEXT;

		struct tuples tuples;
		struct tuples_key reversed_tuples_key;

		get_tuples(skb, &tuples, &iph, &ipv6h, &tcph, &udph, l4proto);
		copy_reversed_tuples(&tuples.five, &reversed_tuples_key);
		if (!refresh_udp_conn_state_timer(&reversed_tuples_key, true))
			return DAE_TC_DROP;
	}

	return DAE_TC_NEXT;
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
	    !(l4proto == IPPROTO_UDP && dport == bpf_htons(53))) {
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
			return DAE_TC_NEXT;
		}
		if (pid_pname) {
			// Store pname in params.flag[2-5] (TASK_COMM_LEN=16 bytes = 4*u32)
			__builtin_memcpy(&params.flag[2], pid_pname->pname,
					 TASK_COMM_LEN);
		}
		pack_mac_to_u32_array(params.mac, ethh->h_source);
		params.saddr = tuples->five.sip.u6_addr32;
		params.daddr = tuples->five.dip.u6_addr32;

		__s64 s64_ret = route(&params);

		if (s64_ret < 0) {
			bpf_printk("shot routing: %d", s64_ret);
			return DAE_TC_DROP;
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
		if (!load_non_syn_tcp_wan_egress(&tuples->five, &outbound, &mark,
						 &must)) {
			// No cached routing. This is a pre-existing connection
			// or server connection. Let it pass.
			return DAE_TC_NEXT;
		}
	}

	if (outbound == OUTBOUND_DIRECT &&
	    mark == 0 // If mark is not zero, we should re-route it.
	) {
		return DAE_TC_NEXT;
	} else if (unlikely(outbound == OUTBOUND_BLOCK)) {
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("SHOT OUTBOUND_BLOCK");
#endif
		return DAE_TC_DROP;
	}

	if (!wan_outbound_is_alive(skb, outbound, IPPROTO_TCP,
				   tuples->five.dport))
		return DAE_TC_DROP;

	if (unlikely(tcp_state_syn)) {
		// Only save non-direct routing to avoid conflicts with LAN ingress.
		// Direct traffic doesn't need control plane processing.
		if (outbound != OUTBOUND_DIRECT || mark != 0 || must) {
			struct routing_result routing_result = {};

			routing_result.outbound = outbound;
			routing_result.mark = mark;
			routing_result.must = must;
			routing_result.dscp = tuples->dscp;
			__builtin_memcpy(routing_result.mac, ethh->h_source,
					 sizeof(ethh->h_source));
			if (pid_pname) {
				__builtin_memcpy(routing_result.pname,
						 pid_pname->pname,
						 TASK_COMM_LEN);
				routing_result.pid = pid_pname->pid;
			}
			bpf_map_update_elem(&routing_tuples_map, &tuples->five,
					    &routing_result, BPF_ANY);
		}
	}

	prep_redirect_to_control_plane(skb, link_h_len, tuples, IPPROTO_TCP, ethh,
				       1, tcph);
	return bpf_redirect(PARAM.dae0_ifindex, 0);
}

static __noinline int
do_tproxy_wan_egress_udp(struct __sk_buff *skb, u32 link_h_len,
			 struct tuples *tuples, struct ethhdr *ethh,
			 struct udphdr *udph)
{
	// Routing. It decides if we redirect traffic to control plane.
	struct route_params params;
	struct pid_pname *pid_pname = NULL;
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
		return DAE_TC_NEXT;
	}

	if (!is_short_lived_udp_traffic(&tuples->five)) {
		struct udp_conn_state *conn_state =
			refresh_udp_conn_state_timer(&tuples->five, false);
		if (!conn_state)
			return DAE_TC_DROP;
		if (conn_state->is_wan_ingress_direction) {
			// Replay (outbound) of an inbound flow => direct.
			return DAE_TC_NEXT;
		}
	}

	if (pid_pname) {
		// Store pname in params.flag[2-5] (TASK_COMM_LEN=16 bytes = 4*u32)
		__builtin_memcpy(&params.flag[2], pid_pname->pname,
				 TASK_COMM_LEN);
	}
	pack_mac_to_u32_array(params.mac, ethh->h_source);
	params.saddr = tuples->five.sip.u6_addr32;
	params.daddr = tuples->five.dip.u6_addr32;

	__s64 s64_ret = route(&params);

	if (s64_ret < 0) {
		bpf_printk("shot routing: %d", s64_ret);
		return DAE_TC_DROP;
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
			__builtin_memcpy(routing_result.mac, ethh->h_source,
					 sizeof(ethh->h_source));
			if (pid_pname) {
				__builtin_memcpy(routing_result.pname,
						 pid_pname->pname,
						 TASK_COMM_LEN);
				routing_result.pid = pid_pname->pid;
			}
			bpf_map_update_elem(&routing_tuples_map, &tuples->five,
					    &routing_result, BPF_ANY);
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
		return DAE_TC_NEXT;
	} else if (unlikely(outbound == OUTBOUND_BLOCK)) {
		return DAE_TC_DROP;
	}

	if (!wan_outbound_is_alive(skb, outbound, IPPROTO_UDP,
				   tuples->five.dport))
		return DAE_TC_DROP;

	prep_redirect_to_control_plane(skb, link_h_len, tuples, IPPROTO_UDP, ethh,
				       1, &dummy_tcph);
	return bpf_redirect(PARAM.dae0_ifindex, 0);
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

/*
 * Keep wan_egress as a BPF subprogram to avoid verifier state explosion on
 * newer kernels (e.g. Debian 6.12), while preserving routing semantics.
 */
static __noinline int do_tproxy_wan_egress(struct __sk_buff *skb, u32 link_h_len)
{
	// Skip packets not from localhost.
	if (skb->ingress_ifindex != NOWHERE_IFINDEX)
		return DAE_TC_NEXT;

	__u32 scratch_key = 0;
	struct wan_egress_parsed *pkt =
		bpf_map_lookup_elem(&wan_egress_scratch_map, &scratch_key);
	if (unlikely(!pkt))
		return DAE_TC_DROP;

	/* Initialize stack bytes for verifier friendliness across subprogram
	 * pointer writes. */
	__builtin_memset(pkt, 0, sizeof(*pkt));
	int ret = parse_wan_egress_packet(skb, link_h_len, pkt);

	if (ret)
		return DAE_TC_NEXT;

	if (pkt->l4proto == IPPROTO_TCP)
		return do_tproxy_wan_egress_tcp(skb, link_h_len, &pkt->tuples,
						&pkt->ethh, &pkt->tcph);
	if (pkt->l4proto == IPPROTO_UDP)
		return do_tproxy_wan_egress_udp(skb, link_h_len, &pkt->tuples,
						&pkt->ethh, &pkt->udph);
	return DAE_TC_NEXT;
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
		return DAE_TC_DROP;

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
	return DAE_TC_PASS;
}

// load_redirect_tuple_fast returns this code when it cannot safely parse via
// direct packet access and should fall back to bpf_skb_load_bytes.
#define LOAD_REDIRECT_TUPLE_FALLBACK 2

static __always_inline int
load_redirect_tuple_fast(const struct __sk_buff *skb,
			 struct redirect_tuple *redirect_tuple)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return LOAD_REDIRECT_TUPLE_FALLBACK;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + ETH_HLEN;

		if ((void *)(iph + 1) > data_end)
			return LOAD_REDIRECT_TUPLE_FALLBACK;
		redirect_tuple->sip.u6_addr32[3] = iph->daddr;
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
load_redirect_tuple_slow(const struct __sk_buff *skb,
			 struct redirect_tuple *redirect_tuple)
{
	int ret;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
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
load_redirect_tuple(const struct __sk_buff *skb,
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
		return DAE_TC_PASS;
	struct redirect_entry *redirect_entry =
		bpf_map_lookup_elem(&redirect_track, &redirect_tuple);

	if (!redirect_entry)
		return DAE_TC_PASS;

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

SEC("sk_skb/stream_parser")
int tproxy_fast_redirect_parser(struct __sk_buff *skb)
{
	return skb->len;
}

SEC("sk_skb/stream_verdict")
int tproxy_fast_redirect_verdict(struct __sk_buff *skb)
{
	struct tuples_key key;
	int verdict;

	if (!get_fast_redirect_key(skb, &key))
		return SK_PASS;

	verdict = bpf_sk_redirect_hash(skb, &fast_sock, &key, 0);
	if (verdict == SK_DROP)
		return SK_PASS;
	return verdict;
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

SEC("license") const char __license[] = "Dual BSD/GPL";
