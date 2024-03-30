// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>

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

#define IPV4_CSUM_OFF(link_h_len) ((link_h_len) + offsetof(struct iphdr, check))
#define IPV4_DST_OFF(link_h_len) ((link_h_len) + offsetof(struct iphdr, daddr))
#define IPV4_SRC_OFF(link_h_len) ((link_h_len) + offsetof(struct iphdr, saddr))
#define IPV6_DST_OFF(link_h_len) ((link_h_len) + offsetof(struct ipv6hdr, daddr))
#define IPV6_SRC_OFF(link_h_len) ((link_h_len) + offsetof(struct ipv6hdr, saddr))

#define PACKET_HOST 0
#define PACKET_OTHERHOST 3

#define NOWHERE_IFINDEX 0
#define LOOPBACK_IFINDEX 1

#define MAX_PARAM_LEN 16
#define MAX_INTERFACE_NUM 256
#ifndef MAX_MATCH_SET_LEN
#define MAX_MATCH_SET_LEN (32 * 2) // Should be sync with common/consts/ebpf.go.
#endif
#define MAX_LPM_SIZE 2048000
#define MAX_LPM_NUM (MAX_MATCH_SET_LEN + 8)
#define MAX_DST_MAPPING_NUM (65536 * 2)
#define MAX_TGID_PNAME_MAPPING_NUM (8192)
#define MAX_COOKIE_PID_PNAME_MAPPING_NUM (65536)
#define MAX_DOMAIN_ROUTING_NUM 65536
#define MAX_ARG_LEN_TO_PROBE 128
#define MAX_ARG_SCANNER_BUFFER_SIZE (TASK_COMM_LEN * 4)
#define IPV6_MAX_EXTENSIONS 4

#define OUTBOUND_DIRECT 0
#define OUTBOUND_BLOCK 1
#define OUTBOUND_MUST_RULES 0xFC
#define OUTBOUND_CONTROL_PLANE_ROUTING 0xFD
#define OUTBOUND_LOGICAL_OR 0xFE
#define OUTBOUND_LOGICAL_AND 0xFF
#define OUTBOUND_LOGICAL_MASK 0xFE

#define IS_WAN 0
#define IS_LAN 1

#define TPROXY_MARK 0x8000000
#define RECOGNIZE 0x2017

#define ESOCKTNOSUPPORT 94 /* Socket type not supported */

enum { BPF_F_CURRENT_NETNS = -1 };

enum {
	DisableL4ChecksumPolicy_EnableL4Checksum,
	DisableL4ChecksumPolicy_Restore,
	DisableL4ChecksumPolicy_SetZero,
};

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
	__type(value, __u32);             // true, false
	__uint(max_entries, 256 * 2 * 2); // outbound * l4proto * ipversion
} outbound_connectivity_map SEC(".maps");

// Sockmap:
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key, __u32);   // 0 is tcp, 1 is udp.
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
	__u8 l4proto;
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
	__u32 tproxy_port;
	__u32 control_plane_pid;
	__u32 dae0_ifindex;
	__u32 dae_netns_id;
	__u8 dae0peer_mac[6];
	__u8 padding[2];
};

static volatile const struct dae_param PARAM = {};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);                      // tgid
	__type(value, __u32[TASK_COMM_LEN / 4]); // process name.
	__uint(max_entries, MAX_TGID_PNAME_MAPPING_NUM);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tgid_pname_map
		SEC(".maps"); // This map is only for old method (redirect mode in WAN).

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct tuples_key);
	__type(value, struct routing_result); // outbound
	__uint(max_entries, MAX_DST_MAPPING_NUM);
	/// NOTICE: It MUST be pinned.
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} routing_tuples_map SEC(".maps");

/* Sockets in fast_sock map are used for fast-redirecting via
 * sk_msg/fast_redirect. Sockets are automactically deleted from map once
 * closed, so we don't need to worry about stale entries.
 */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct tuples_key);
	__type(value, __u64);
	__uint(max_entries, 65535);
} fast_sock SEC(".maps");

// Link to type:
#define LinkType_None 0
#define LinkType_Ethernet 1
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);   // ifindex
	__type(value, __u32); // link length
	__uint(max_entries, MAX_INTERFACE_NUM);
	/// NOTICE: No persistence.
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} linklen_map SEC(".maps");

// LPM key:
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, __u32);
	__type(value, struct lpm_key);
	__uint(max_entries, 3);
} lpm_key_map SEC(".maps");

// h_sport, h_dport:
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, __u32);
	__type(value, __u16);
	__uint(max_entries, 2);
} h_port_map SEC(".maps");

// l4proto, ipversion:
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 2);
} l4proto_ipversion_map SEC(".maps");

// Interface Ips:
struct if_params {
	bool rx_cksm_offload;
	bool tx_l4_cksm_ip4_offload;
	bool tx_l4_cksm_ip6_offload;
	bool use_nonstandard_offload_algorithm;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);              // ifindex
	__type(value, struct if_params); // ip
	__uint(max_entries, MAX_INTERFACE_NUM);
	/// NOTICE: No persistence.
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifindex_params_map SEC(".maps");

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

enum __attribute__((packed)) MatchType {
	/// WARNING: MUST SYNC WITH common/consts/ebpf.go.
	MatchType_DomainSet,
	MatchType_IpSet,
	MatchType_SourceIpSet,
	MatchType_Port,
	MatchType_SourcePort,
	MatchType_L4Proto,
	MatchType_IpVersion,
	MatchType_Mac,
	MatchType_ProcessName,
	MatchType_Dscp,
	MatchType_Fallback,
};

enum L4ProtoType {
	L4ProtoType_TCP = 1,
	L4ProtoType_UDP = 2,
	L4ProtoType_X = 3,
};

enum IpVersionType {
	IpVersionType_4 = 1,
	IpVersionType_6 = 2,
	IpVersionType_X = 3,
};

struct port_range {
	__u16 port_start;
	__u16 port_end;
};

/*
 * Rule is like as following:
 *
 * domain(geosite:cn, suffix: google.com) && l4proto(tcp) -> my_group
 *
 * pseudocode: domain(geosite:cn || suffix:google.com) && l4proto(tcp) -> my_group
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

// Functions:

static __always_inline __u8 ipv4_get_dscp(const struct iphdr *iph)
{
	return (iph->tos & 0xfc) >> 2;
}

static __always_inline __u8 ipv6_get_dscp(const struct ipv6hdr *ipv6h)
{
	return (ipv6h->priority << 2) + (ipv6h->flow_lbl[0] >> 6);
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
		__builtin_memcpy(&tuples->five.dip, &ipv6h->daddr, IPV6_BYTE_LENGTH);
		__builtin_memcpy(&tuples->five.sip, &ipv6h->saddr, IPV6_BYTE_LENGTH);

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
#if __clang_major__ >= 10
	return ((__be64 *)x)[0] == ((__be64 *)y)[0] &&
	((__be64 *)x)[1] == ((__be64 *)y)[1];

	// return x[0] == y[0] && x[1] == y[1] && x[2] == y[2] && x[3] == y[3];
#else
	return __builtin_bcmp(x, y, IPV6_BYTE_LENGTH) == 0;
#endif
}

static __always_inline int
handle_ipv6_extensions(const struct __sk_buff *skb, __u32 offset, __u32 hdr,
		       struct icmp6hdr *icmp6h, struct tcphdr *tcph,
		       struct udphdr *udph, __u8 *ihl, __u8 *l4proto) {
	__u8 hdr_length = 0;
	__u8 nexthdr = 0;
	*ihl = sizeof(struct ipv6hdr) / 4;
	int ret;
	// We only process TCP and UDP traffic.

	// Unroll can give less instructions but more memory consumption when loading.
	// We disable it here to support more poor memory devices.
	// #pragma unroll
	for (int i = 0; i < IPV6_MAX_EXTENSIONS;
			 i++, offset += hdr_length, hdr = nexthdr, *ihl += hdr_length / 4) {
		if (hdr_length % 4) {
			bpf_printk("IPv6 extension length is not multiples of 4");
			return 1;
		}
		// See control/control_plane.go.

		switch (hdr) {
		case IPPROTO_ICMPV6:
			*l4proto = hdr;
			hdr_length = sizeof(struct icmp6hdr);
			// Assume ICMPV6 as a level 4 protocol.
			ret = bpf_skb_load_bytes(skb, offset, icmp6h, hdr_length);
			if (ret) {
				bpf_printk("not a valid IPv6 packet");
				return -EFAULT;
			}
			return 0;

		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
			ret = bpf_skb_load_bytes(skb, offset + 1, &hdr_length, sizeof(hdr_length));
			if (ret) {
				bpf_printk("not a valid IPv6 packet");
				return -EFAULT;
			}

special_n1:
			ret = bpf_skb_load_bytes(skb, offset, &nexthdr, sizeof(nexthdr));
			if (ret) {
				bpf_printk("not a valid IPv6 packet");
				return -EFAULT;
			}
			break;
		case IPPROTO_FRAGMENT:
			hdr_length = 4;
			goto special_n1;
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			*l4proto = hdr;
			if (hdr == IPPROTO_TCP) {
				// Upper layer;
				ret = bpf_skb_load_bytes(skb, offset, tcph, sizeof(struct tcphdr));
				if (ret) {
					bpf_printk("not a valid IPv6 packet");
					return -EFAULT;
				}
			} else if (hdr == IPPROTO_UDP) {
				// Upper layer;
				ret = bpf_skb_load_bytes(skb, offset, udph, sizeof(struct udphdr));
				if (ret) {
					bpf_printk("not a valid IPv6 packet");
					return -EFAULT;
				}
			} else {
				// Unknown hdr.
				bpf_printk("Unexpected hdr.");
				return 1;
			}
			return 0;
		default:
			/// EXPECTED: Maybe ICMP, etc.
			// bpf_printk("IPv6 but unrecognized extension protocol: %u", hdr);
			return 1;
		}
	}
	bpf_printk("exceeds IPV6_MAX_EXTENSIONS limit");
	return 1;
}

static __always_inline int
parse_transport(const struct __sk_buff *skb, __u32 link_h_len,
		struct ethhdr *ethh, struct iphdr *iph, struct ipv6hdr *ipv6h,
		struct icmp6hdr *icmp6h, struct tcphdr *tcph,
		struct udphdr *udph, __u8 *ihl, __u8 *l4proto) {
	__u32 offset = 0;
	int ret;

	if (link_h_len == ETH_HLEN) {
		ret = bpf_skb_load_bytes(skb, offset, ethh, sizeof(struct ethhdr));
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
	//            bpf_htons(ETH_P_IP), bpf_htons(ETH_P_IPV6));
	if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
		ret = bpf_skb_load_bytes(skb, offset, iph, sizeof(struct iphdr));
		if (ret)
			return -EFAULT;
		// Skip ipv4hdr and options for next hdr.
		offset += iph->ihl * 4;

		// We only process TCP and UDP traffic.
		*l4proto = iph->protocol;
		switch (iph->protocol) {
		case IPPROTO_TCP: {
			ret = bpf_skb_load_bytes(skb, offset, tcph, sizeof(struct tcphdr));
			if (ret) {
				// Not a complete tcphdr.
				return -EFAULT;
			}
		} break;
		case IPPROTO_UDP: {
			ret = bpf_skb_load_bytes(skb, offset, udph, sizeof(struct udphdr));
			if (ret) {
				// Not a complete udphdr.
				return -EFAULT;
			}
		} break;
		default:
			return 1;
		}
		*ihl = iph->ihl;
		return 0;
	} else if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
		ret = bpf_skb_load_bytes(skb, offset, ipv6h, sizeof(struct ipv6hdr));
		if (ret) {
			bpf_printk("not a valid IPv6 packet");
			return -EFAULT;
		}

		offset += sizeof(struct ipv6hdr);

		return handle_ipv6_extensions(skb, offset, ipv6h->nexthdr, icmp6h, tcph,
				  udph, ihl, l4proto);
	} else {
		/// EXPECTED: Maybe ICMP, MPLS, etc.
		// bpf_printk("IP but not supported packet: protocol is %u",
		// iph->protocol);
		// bpf_printk("unknown link proto: %u", bpf_ntohl(skb->protocol));
		return 1;
	}
}

// Do not use __always_inline here because this function is too heavy.
// low -> high: outbound(8b) mark(32b) unused(23b) sign(1b)
static __s64 __attribute__((noinline))
route(const __u32 flag[8], const void *l4hdr, const __be32 saddr[4],
      const __be32 daddr[4], const __be32 mac[4])
{
#define _l4proto_type flag[0]
#define _ipversion_type flag[1]
#define _pname (&flag[2])
#define _is_wan flag[2]
#define _dscp flag[6]

	int ret;
	struct lpm_key *lpm_key;
	__u32 key = MatchType_L4Proto;
	__u16 h_dport;
	__u16 h_sport;
	struct lpm_key lpm_key_instance = {
		.trie_key = { IPV6_BYTE_LENGTH * 8, {} },
	};

	/// TODO: BPF_MAP_UPDATE_BATCH ?
	ret = bpf_map_update_elem(&l4proto_ipversion_map, &key, &_l4proto_type, BPF_ANY);
	if (unlikely(ret))
		return ret;
	key = MatchType_IpVersion;
	ret = bpf_map_update_elem(&l4proto_ipversion_map, &key, &_ipversion_type, BPF_ANY);
	if (unlikely(ret))
		return ret;

	// Variables for further use.
	if (_l4proto_type == L4ProtoType_TCP) {
		h_dport = bpf_ntohs(((struct tcphdr *)l4hdr)->dest);
		h_sport = bpf_ntohs(((struct tcphdr *)l4hdr)->source);
	} else {
		h_dport = bpf_ntohs(((struct udphdr *)l4hdr)->dest);
		h_sport = bpf_ntohs(((struct udphdr *)l4hdr)->source);
	}

	key = MatchType_SourcePort;
	if (unlikely((ret = bpf_map_update_elem(&h_port_map, &key, &h_sport, BPF_ANY))))
		return ret;
	key = MatchType_Port;
	if (unlikely((ret = bpf_map_update_elem(&h_port_map, &key, &h_dport, BPF_ANY))))
		return ret;

	__builtin_memcpy(lpm_key_instance.data, daddr, IPV6_BYTE_LENGTH);
	key = MatchType_IpSet;
	ret = bpf_map_update_elem(&lpm_key_map, &key, &lpm_key_instance, BPF_ANY);
	if (unlikely(ret))
		return ret;
	__builtin_memcpy(lpm_key_instance.data, saddr, IPV6_BYTE_LENGTH);
	key = MatchType_SourceIpSet;
	ret = bpf_map_update_elem(&lpm_key_map, &key, &lpm_key_instance, BPF_ANY);
	if (unlikely(ret))
		return ret;
	__builtin_memcpy(lpm_key_instance.data, mac, IPV6_BYTE_LENGTH);
	key = MatchType_Mac;
	ret = bpf_map_update_elem(&lpm_key_map, &key, &lpm_key_instance, BPF_ANY);
	if (unlikely(ret))
		return ret;

	struct map_lpm_type *lpm;
	struct match_set *match_set;
	// Rule is like: domain(suffix:baidu.com, suffix:google.com) && port(443) ->
	// proxy Subrule is like: domain(suffix:baidu.com, suffix:google.com) Match
	// set is like: suffix:baidu.com
	volatile __u8 isdns_must_goodsubrule_badrule =
			(h_dport == 53 && _l4proto_type == L4ProtoType_UDP) << 3;
	struct domain_routing *domain_routing;
	__u32 *p_u32;
	__u16 *p_u16;

	// Unroll can give less instructions but more memory consumption when loading.
	// We disable it here to support more poor memory devices.
#ifdef __UNROLL_ROUTE_LOOP
#pragma unroll
#endif
	for (__u32 i = 0; i < MAX_MATCH_SET_LEN; i++) {
		__u32 k = i; // Clone to pass code checker.

		match_set = bpf_map_lookup_elem(&routing_map, &k);
		if (unlikely(!match_set))
			return -EFAULT;
		if (isdns_must_goodsubrule_badrule & 0b11) {
#ifdef __DEBUG_ROUTING
			key = match_set->type;
			bpf_printk("key(match_set->type): %llu", key);
			bpf_printk("Skip to judge. bad_rule: %d, good_subrule: %d",
				   isdns_must_goodsubrule_badrule & 0b10,
				   isdns_must_goodsubrule_badrule & 0b1);
#endif
			goto before_next_loop;
		}
		key = match_set->type;
#ifdef __DEBUG_ROUTING
		bpf_printk("key(match_set->type): %llu", key);
#endif
		lpm_key = bpf_map_lookup_elem(&lpm_key_map, &key);
		if (lpm_key) {
#ifdef __DEBUG_ROUTING
			bpf_printk("CHECK: lpm_key_map, match_set->type: %u, not: %d, outbound: %u",
				   match_set->type, match_set->not, match_set->outbound);
			bpf_printk("\tip: %pI6", lpm_key->data);
#endif
			lpm = bpf_map_lookup_elem(&lpm_array_map, &match_set->index);
			if (unlikely(!lpm))
				return -EFAULT;
			if (bpf_map_lookup_elem(lpm, lpm_key)) {
				// match_set hits.
				isdns_must_goodsubrule_badrule |= 0b10;
			}
		} else if ((p_u16 = bpf_map_lookup_elem(&h_port_map, &key))) {
#ifdef __DEBUG_ROUTING
			bpf_printk("CHECK: h_port_map, match_set->type: %u, not: %d, outbound: %u",
				   match_set->type, match_set->not, match_set->outbound);
			bpf_printk("\tport: %u, range: [%u, %u]", *p_u16,
				   match_set->port_range.port_start,
				   match_set->port_range.port_end);
#endif
			if (*p_u16 >= match_set->port_range.port_start &&
			    *p_u16 <= match_set->port_range.port_end) {
				isdns_must_goodsubrule_badrule |= 0b10;
			}
		} else if ((p_u32 = bpf_map_lookup_elem(&l4proto_ipversion_map, &key))) {
#ifdef __DEBUG_ROUTING
			bpf_printk("CHECK: l4proto_ipversion_map, match_set->type: %u, not: %d, outbound: %u",
				   match_set->type, match_set->not, match_set->outbound);
#endif
			if (*p_u32 & *(__u32 *)&match_set->__value)
				isdns_must_goodsubrule_badrule |= 0b10;
		} else {
			switch (key) {
			case MatchType_DomainSet:
#ifdef __DEBUG_ROUTING
				bpf_printk("CHECK: domain, match_set->type: %u, not: %d, outbound: %u",
					   match_set->type, match_set->not, match_set->outbound);
#endif

				// Get domain routing bitmap.
				domain_routing = bpf_map_lookup_elem(&domain_routing_map, daddr);

				// We use key instead of k to pass checker.
				if (domain_routing &&
				    (domain_routing->bitmap[i / 32] >> (i % 32)) & 1)
					isdns_must_goodsubrule_badrule |= 0b10;
				break;
			case MatchType_ProcessName:
				if (_is_wan && equal16(match_set->pname, _pname))
					isdns_must_goodsubrule_badrule |= 0b10;
				break;
			case MatchType_Dscp:
				if (_dscp == match_set->dscp)
					isdns_must_goodsubrule_badrule |= 0b10;
				break;
			case MatchType_Fallback:
#ifdef __DEBUG_ROUTING
				bpf_printk("CHECK: hit fallback");
#endif
				isdns_must_goodsubrule_badrule |= 0b10;
				break;
			default:
#ifdef __DEBUG_ROUTING
				bpf_printk("CHECK: <unknown>, match_set->type: %u, not: %d, outbound: %u",
					   match_set->type, match_set->not, match_set->outbound);
#endif
	return -EINVAL;
			}
		}

before_next_loop:
#ifdef __DEBUG_ROUTING
		bpf_printk("good_subrule: %d, bad_rule: %d",
			   isdns_must_goodsubrule_badrule & 0b10,
			   isdns_must_goodsubrule_badrule & 0b1);
#endif
		if (match_set->outbound != OUTBOUND_LOGICAL_OR) {
			// This match_set reaches the end of subrule.
			// We are now at end of rule, or next match_set belongs to another
			// subrule.

			if ((isdns_must_goodsubrule_badrule & 0b10) > 0 == match_set->not) {
				// This subrule does not hit.
				isdns_must_goodsubrule_badrule |= 0b1;
			}

			// Reset good_subrule.
			isdns_must_goodsubrule_badrule &= ~0b10;
		}
#ifdef __DEBUG_ROUTING
		bpf_printk("_bad_rule: %d", isdns_must_goodsubrule_badrule & 0b1);
#endif
		if ((match_set->outbound & OUTBOUND_LOGICAL_MASK) !=
	OUTBOUND_LOGICAL_MASK) {
			// Tail of a rule (line).
			// Decide whether to hit.
			if (!(isdns_must_goodsubrule_badrule & 0b1)) {
#ifdef __DEBUG_ROUTING
				bpf_printk("MATCHED: match_set->type: %u, match_set->not: %d",
					   match_set->type, match_set->not);
#endif

				// DNS requests should routed by control plane if outbound is not
				// must_direct.

				if (unlikely(match_set->outbound == OUTBOUND_MUST_RULES)) {
					isdns_must_goodsubrule_badrule |= 0b100;
				} else {
					if (isdns_must_goodsubrule_badrule & 0b100)
						match_set->must = true;
					if (!match_set->must &&
					    (isdns_must_goodsubrule_badrule & 0b1000)) {
						return (__s64)OUTBOUND_CONTROL_PLANE_ROUTING |
							((__s64)match_set->mark << 8) |
							((__s64)match_set->must << 40);
					} else {
						return (__s64)match_set->outbound |
							((__s64)match_set->mark << 8) |
							((__s64)match_set->must << 40);
					}
				}
			}
			isdns_must_goodsubrule_badrule &= ~0b1;
		}
	}
	bpf_printk("No match_set hits. Did coder forget to sync common/consts/ebpf.go with enum MatchType?");
	return -EPERM;
#undef _l4proto_type
#undef _ipversion_type
#undef _pname
#undef _is_wan
#undef _dscp
}

static __always_inline __u32 get_link_h_len(__u32 ifindex,
					    volatile __u32 *link_h_len)
{
	__u32 *plink_h_len = bpf_map_lookup_elem(&linklen_map, &ifindex);

	if (!plink_h_len)
		return -EIO;
	*link_h_len = *plink_h_len;
	return 0;
}

static __always_inline int
assign_listener(struct __sk_buff *skb, __u8 l4proto)
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

static __always_inline void
prep_redirect_to_control_plane(struct __sk_buff *skb, __u32 link_h_len,
			       struct tuples *tuples, __u8 l4proto,
			  struct ethhdr *ethh, __u8 from_wan,
			  struct tcphdr *tcph)
{
	/* Redirect from L3 dev to L2 dev, e.g. wg0 -> veth */
	if (!link_h_len) {
		__u16 l3proto = skb->protocol;

		bpf_skb_change_head(skb, sizeof(struct ethhdr), 0);
		bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
				    &l3proto, sizeof(l3proto), 0);
	}

	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
			    (void *)&PARAM.dae0peer_mac, sizeof(ethh->h_dest), 0);

	struct redirect_tuple redirect_tuple = {};

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		redirect_tuple.sip.u6_addr32[3] = tuples->five.sip.u6_addr32[3];
		redirect_tuple.dip.u6_addr32[3] = tuples->five.dip.u6_addr32[3];
	} else {
		__builtin_memcpy(&redirect_tuple.sip, &tuples->five.sip, IPV6_BYTE_LENGTH);
		__builtin_memcpy(&redirect_tuple.dip, &tuples->five.dip, IPV6_BYTE_LENGTH);
	}
	redirect_tuple.l4proto = l4proto;
	struct redirect_entry redirect_entry = {};

	redirect_entry.ifindex = skb->ifindex;
	redirect_entry.from_wan = from_wan;
	__builtin_memcpy(redirect_entry.smac, ethh->h_source, sizeof(ethh->h_source));
	__builtin_memcpy(redirect_entry.dmac, ethh->h_dest, sizeof(ethh->h_dest));
	bpf_map_update_elem(&redirect_track, &redirect_tuple, &redirect_entry, BPF_ANY);

	skb->cb[0] = TPROXY_MARK;
	skb->cb[1] = 0;
	if ((l4proto == IPPROTO_TCP && tcph->syn) || l4proto == IPPROTO_UDP)
		skb->cb[1] = l4proto;
}

SEC("tc/ingress")
int tproxy_lan_ingress(struct __sk_buff *skb)
{
	struct ethhdr ethh;
	struct iphdr iph;
	struct ipv6hdr ipv6h;
	struct icmp6hdr icmp6h;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 ihl;
	__u8 l4proto;
	__u32 link_h_len;

	if (get_link_h_len(skb->ifindex, &link_h_len))
		return TC_ACT_OK;
	int ret = parse_transport(skb, link_h_len, &ethh, &iph, &ipv6h, &icmp6h,
				  &tcph, &udph, &ihl, &l4proto);
	if (ret) {
		bpf_printk("parse_transport: %d", ret);
		return TC_ACT_OK;
	}
	if (l4proto == IPPROTO_ICMPV6)
		return TC_ACT_OK;

	// Prepare five tuples.
	struct tuples tuples;

	get_tuples(skb, &tuples, &iph, &ipv6h, &tcph, &udph, l4proto);

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
	// Socket lookup and assign skb to existing socket connection.
	struct bpf_sock_tuple tuple = {0};
	__u32 tuple_size;
	struct bpf_sock *sk;
	__u32 flag[8];
	void *l4hdr;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		tuple.ipv4.daddr = tuples.five.dip.u6_addr32[3];
		tuple.ipv4.saddr = tuples.five.sip.u6_addr32[3];
		tuple.ipv4.dport = tuples.five.dport;
		tuple.ipv4.sport = tuples.five.sport;
		tuple_size = sizeof(tuple.ipv4);
	} else {
		__builtin_memcpy(tuple.ipv6.daddr, &tuples.five.dip, IPV6_BYTE_LENGTH);
		__builtin_memcpy(tuple.ipv6.saddr, &tuples.five.sip, IPV6_BYTE_LENGTH);
		tuple.ipv6.dport = tuples.five.dport;
		tuple.ipv6.sport = tuples.five.sport;
		tuple_size = sizeof(tuple.ipv6);
	}

	if (l4proto == IPPROTO_TCP) {
		// TCP.
		if (tcph.syn && !tcph.ack)
			goto new_connection;

		sk = bpf_skc_lookup_tcp(skb, &tuple, tuple_size, PARAM.dae_netns_id, 0);
		if (sk) {
			if (sk->state != BPF_TCP_LISTEN) {
				bpf_sk_release(sk);
				goto control_plane;
			}
			bpf_sk_release(sk);
		}
	}

// Routing for new connection.
new_connection:
	__builtin_memset(flag, 0, sizeof(flag));
	if (l4proto == IPPROTO_TCP) {
		if (!(tcph.syn && !tcph.ack)) {
			// Not a new TCP connection.
			// Perhaps single-arm.
			return TC_ACT_OK;
		}
		l4hdr = &tcph;
		flag[0] = L4ProtoType_TCP;
	} else {
		l4hdr = &udph;
		flag[0] = L4ProtoType_UDP;
	}
	if (skb->protocol == bpf_htons(ETH_P_IP))
		flag[1] = IpVersionType_4;
	else
		flag[1] = IpVersionType_6;
	flag[6] = tuples.dscp;
	__be32 mac[4] = {
			0,
			0,
			bpf_htonl((ethh.h_source[0] << 8) + (ethh.h_source[1])),
			bpf_htonl((ethh.h_source[2] << 24) + (ethh.h_source[3] << 16) +
		(ethh.h_source[4] << 8) + (ethh.h_source[5])),
	};
	__s64 s64_ret;

	s64_ret = route(flag, l4hdr, tuples.five.sip.u6_addr32, tuples.five.dip.u6_addr32, mac);
	if (s64_ret < 0) {
		bpf_printk("shot routing: %d", s64_ret);
		return TC_ACT_SHOT;
	}
	struct routing_result routing_result = {0};

	routing_result.outbound = s64_ret;
	routing_result.mark = s64_ret >> 8;
	routing_result.must = (s64_ret >> 40) & 1;
	routing_result.dscp = tuples.dscp;
	__builtin_memcpy(routing_result.mac, ethh.h_source, sizeof(routing_result.mac));
	/// NOTICE: No pid pname info for LAN packet.
	// // Maybe this packet is also in the host (such as docker) ?
	// // I tried and it is false.
	// __u64 cookie = bpf_get_socket_cookie(skb);
	// struct pid_pname *pid_pname = bpf_map_lookup_elem(&cookie_pid_map,
	// &cookie); if (pid_pname) {
	//   __builtin_memcpy(routing_result.pname, pid_pname->pname, TASK_COMM_LEN);
	//   routing_result.pid = pid_pname->pid;
	// }

	// Save routing result.
	ret = bpf_map_update_elem(&routing_tuples_map, &tuples.five, &routing_result, BPF_ANY);
	if (ret) {
		bpf_printk("shot save routing result: %d", ret);
		return TC_ACT_SHOT;
	}
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
	if (l4proto == IPPROTO_TCP) {
		bpf_printk("tcp(lan): outbound: %u, target: %pI6:%u", ret,
			   tuples.five.dip.u6_addr32, bpf_ntohs(tuples.five.dport));
	} else {
		bpf_printk("udp(lan): outbound: %u, target: %pI6:%u",
			   routing_result.outbound, tuples.five.dip.u6_addr32,
		bpf_ntohs(tuples.five.dport));
	}
#endif
	if (routing_result.outbound == OUTBOUND_DIRECT) {
		skb->mark = routing_result.mark;
		goto direct;
	} else if (unlikely(routing_result.outbound == OUTBOUND_BLOCK)) {
		goto block;
	}

	// Check outbound connectivity in specific ipversion and l4proto.
	struct outbound_connectivity_query q = {0};

	q.outbound = routing_result.outbound;
	q.ipversion = skb->protocol == bpf_htons(ETH_P_IP) ? 4 : 6;
	q.l4proto = l4proto;
	__u32 *alive;

	alive = bpf_map_lookup_elem(&outbound_connectivity_map, &q);
	if (alive && *alive == 0 &&
	    !(l4proto == IPPROTO_UDP && tuples.five.dport == bpf_htons(53))) {
		// Outbound is not alive. Dns is an exception.
		goto block;
	}

	// Assign to control plane.
control_plane:
	prep_redirect_to_control_plane(skb, link_h_len, &tuples, l4proto, &ethh, 0, &tcph);
	return bpf_redirect(PARAM.dae0_ifindex, 0);

direct:
	return TC_ACT_OK;

block:
	return TC_ACT_SHOT;
}

// Cookie will change after the first packet, so we just use it for
// handshake.
static __always_inline bool pid_is_control_plane(struct __sk_buff *skb,
						 struct pid_pname **p) {
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
	if ((skb->mark & 0x100) == 0x100) {
		bpf_printk("No pid_pname found. But it should not happen");
		/*
		 *		if (l4proto == IPPROTO_TCP) {
		 *if (tcph.syn && !tcph.ack) {
		 *	bpf_printk("No pid_pname found. But it should not happen: local:%u "
		 *	     "(%u)[%llu]",
		 *	     bpf_ntohs(sport), l4proto, cookie);
		 *} else {
		 *	bpf_printk("No pid_pname found. But it should not happen: (Old "
		 *	     "Connection): local:%u "
		 *	     "(%u)[%llu]",
		 *	     bpf_ntohs(sport), l4proto, cookie);
		 *}
		 *		} else {
		 *bpf_printk("No pid_pname found. But it should not happen: local:%u "
		 *	   "(%u)[%llu]",
		 *	   bpf_ntohs(sport), l4proto, cookie);
		 *		}
		 */
		return true;
	}
	return false;
}

// Routing and redirect the packet back.
// We cannot modify the dest address here. So we cooperate with wan_ingress.
SEC("tc/wan_egress")
int tproxy_wan_egress(struct __sk_buff *skb)
{
	// Skip packets not from localhost.
	if (skb->ingress_ifindex != NOWHERE_IFINDEX)
		return TC_ACT_OK;
	// if ((skb->mark & 0x80) == 0x80) {
	//   return TC_ACT_OK;
	// }

	struct ethhdr ethh;
	struct iphdr iph;
	struct ipv6hdr ipv6h;
	struct icmp6hdr icmp6h;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 ihl;
	__u8 l4proto;
	__u32 link_h_len;

	if (get_link_h_len(skb->ifindex, &link_h_len))
		return TC_ACT_OK;
	bool tcp_state_syn;
	int ret = parse_transport(skb, link_h_len, &ethh, &iph, &ipv6h, &icmp6h,
			    &tcph, &udph, &ihl, &l4proto);
	if (ret)
		return TC_ACT_OK;
	if (l4proto == IPPROTO_ICMPV6)
		return TC_ACT_OK;

	// Backup for further use.
	struct tuples tuples;

	get_tuples(skb, &tuples, &iph, &ipv6h, &tcph, &udph, l4proto);

	// Normal packets.
	if (l4proto == IPPROTO_TCP) {
		// Backup for further use.
		tcp_state_syn = tcph.syn && !tcph.ack;
		__u8 outbound;
		bool must;
		__u32 mark;
		struct pid_pname *pid_pname = NULL;

		if (unlikely(tcp_state_syn)) {
			// New TCP connection.
			// bpf_printk("[%X]New Connection", bpf_ntohl(tcph.seq));
			__u32 flag[8] = {L4ProtoType_TCP}; // TCP

			if (skb->protocol == bpf_htons(ETH_P_IP))
				flag[1] = IpVersionType_4;
			else
				flag[1] = IpVersionType_6;
			flag[6] = tuples.dscp;
			if (pid_is_control_plane(skb, &pid_pname)) {
				// From control plane. Direct.
				return TC_ACT_OK;
			}
			if (pid_pname) {
				// 2, 3, 4, 5
				__builtin_memcpy(&flag[2], pid_pname->pname, TASK_COMM_LEN);
			}
			__be32 mac[4] = {
				0,
				0,
				bpf_htonl((ethh.h_source[0] << 8) + (ethh.h_source[1])),
				bpf_htonl((ethh.h_source[2] << 24) + (ethh.h_source[3] << 16) +
				(ethh.h_source[4] << 8) + (ethh.h_source[5])),
			};
			__s64 s64_ret;

			s64_ret = route(flag, &tcph, tuples.five.sip.u6_addr32,
					tuples.five.dip.u6_addr32, mac);
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

			bpf_printk("tcp(wan): from %pI6:%u [PID %u]", tuples.five.sip.u6_addr32,
				   bpf_ntohs(tuples.five.sport), pid);
			bpf_printk("tcp(wan): outbound: %u, %pI6:%u", outbound,
				   tuples.five.dip.u6_addr32, bpf_ntohs(tuples.five.dport));
#endif
		} else {
			// bpf_printk("[%X]Old Connection", bpf_ntohl(tcph.seq));
			// The TCP connection exists.
			struct routing_result *routing_result =
				bpf_map_lookup_elem(&routing_tuples_map, &tuples.five);

			if (!routing_result) {
				// Do not impact previous connections and server connections.
				return TC_ACT_OK;
			}
			outbound = routing_result->outbound;
			mark = routing_result->mark;
			must = routing_result->must;
		}

		if (outbound == OUTBOUND_DIRECT &&
		    mark == 0 // If mark is not zero, we should re-route it, so we send it
		    // to control plane in WAN.
		) {
			return TC_ACT_OK;
		} else if (unlikely(outbound == OUTBOUND_BLOCK)) {
			return TC_ACT_SHOT;
		}
		// Rewrite to control plane.

		// Check outbound connectivity in specific ipversion and l4proto.
		struct outbound_connectivity_query q = {0};

		q.outbound = outbound;
		q.ipversion = skb->protocol == bpf_htons(ETH_P_IP) ? 4 : 6;
		q.l4proto = l4proto;
		__u32 *alive;

		alive = bpf_map_lookup_elem(&outbound_connectivity_map, &q);
		if (alive && *alive == 0 &&
		    !(l4proto == IPPROTO_UDP && tuples.five.dport == bpf_htons(53))) {
			// Outbound is not alive. Dns is an exception.
			return TC_ACT_SHOT;
		}

		if (unlikely(tcp_state_syn)) {
			struct routing_result routing_result = {};

			routing_result.outbound = outbound;
			routing_result.mark = mark;
			routing_result.must = must;
			routing_result.dscp = tuples.dscp;
			__builtin_memcpy(routing_result.mac, ethh.h_source,
					 sizeof(ethh.h_source));
			if (pid_pname) {
				__builtin_memcpy(routing_result.pname,
						 pid_pname->pname, TASK_COMM_LEN);
				routing_result.pid = pid_pname->pid;
			}
			bpf_map_update_elem(&routing_tuples_map, &tuples.five,
					    &routing_result, BPF_ANY);
		}

	} else if (l4proto == IPPROTO_UDP) {
		// Routing. It decides if we redirect traffic to control plane.
		__u32 flag[8] = {L4ProtoType_UDP};

		if (skb->protocol == bpf_htons(ETH_P_IP))
			flag[1] = IpVersionType_4;
		else
			flag[1] = IpVersionType_6;
		flag[6] = tuples.dscp;
		struct pid_pname *pid_pname;

		if (pid_is_control_plane(skb, &pid_pname)) {
			// From control plane. Direct.
			return TC_ACT_OK;
		}
		if (pid_pname) {
			// 2, 3, 4, 5
			__builtin_memcpy(&flag[2], pid_pname->pname, TASK_COMM_LEN);
		}
		__be32 mac[4] = {
	0,
	0,
	bpf_htonl((ethh.h_source[0] << 8) + (ethh.h_source[1])),
	bpf_htonl((ethh.h_source[2] << 24) + (ethh.h_source[3] << 16) +
		  (ethh.h_source[4] << 8) + (ethh.h_source[5])),
		};
		__s64 s64_ret;

		s64_ret = route(flag, &udph, tuples.five.sip.u6_addr32,
				tuples.five.dip.u6_addr32, mac);
		if (s64_ret < 0) {
			bpf_printk("shot routing: %d", s64_ret);
			return TC_ACT_SHOT;
		}
		// Construct new hdr to encap.
		struct routing_result routing_result = {};

		routing_result.outbound = s64_ret;
		routing_result.mark = s64_ret >> 8;
		routing_result.must = (s64_ret >> 40) & 1;
		routing_result.dscp = tuples.dscp;
		__builtin_memcpy(routing_result.mac, ethh.h_source, sizeof(ethh.h_source));
		if (pid_pname) {
			__builtin_memcpy(routing_result.pname, pid_pname->pname,
					 TASK_COMM_LEN);
			routing_result.pid = pid_pname->pid;
		}
		bpf_map_update_elem(&routing_tuples_map, &tuples.five,
				    &routing_result, BPF_ANY);
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		__u32 pid = pid_pname ? pid_pname->pid : 0;

		bpf_printk("udp(wan): from %pI6:%u [PID %u]",
			   tuples.five.sip.u6_addr32, bpf_ntohs(tuples.five.sport),
			   pid);
		bpf_printk("udp(wan): outbound: %u, %pI6:%u",
			   routing_result.outbound, tuples.five.dip.u6_addr32,
			   bpf_ntohs(tuples.five.dport));
#endif

		if (routing_result.outbound == OUTBOUND_DIRECT && routing_result.mark == 0
	// If mark is not zero, we should re-route it, so we send it to control
	// plane in WAN.
		) {
			return TC_ACT_OK;
		} else if (unlikely(routing_result.outbound == OUTBOUND_BLOCK)) {
			return TC_ACT_SHOT;
		}

		// Rewrite to control plane.

		// Check outbound connectivity in specific ipversion and l4proto.
		struct outbound_connectivity_query q = {0};

		q.outbound = routing_result.outbound;
		q.ipversion = skb->protocol == bpf_htons(ETH_P_IP) ? 4 : 6;
		q.l4proto = l4proto;
		__u32 *alive;

		alive = bpf_map_lookup_elem(&outbound_connectivity_map, &q);
		if (alive && *alive == 0 &&
		    !(l4proto == IPPROTO_UDP && tuples.five.dport == bpf_htons(53))) {
			// Outbound is not alive. Dns is an exception.
			return TC_ACT_SHOT;
		}
	}

	prep_redirect_to_control_plane(skb, link_h_len, &tuples, l4proto, &ethh, 1, &tcph);
	return bpf_redirect(PARAM.dae0_ifindex, 0);
}

SEC("tc/dae0peer_ingress")
int tproxy_dae0peer_ingress(struct __sk_buff *skb)
{
	/* Only packets redirected from wan_egress or lan_ingress have this cb mark. */
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

SEC("tc/dae0_ingress")
int tproxy_dae0_ingress(struct __sk_buff *skb)
{
	struct ethhdr ethh;
	struct iphdr iph;
	struct ipv6hdr ipv6h;
	struct icmp6hdr icmp6h;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 ihl;
	__u8 l4proto;
	__u32 link_h_len = 14;

	if (parse_transport(skb, link_h_len, &ethh, &iph, &ipv6h, &icmp6h,
			    &tcph, &udph, &ihl, &l4proto))
		return TC_ACT_OK;
	struct tuples tuples;

	get_tuples(skb, &tuples, &iph, &ipv6h, &tcph, &udph, l4proto);

	// reverse the tuple!
	struct redirect_tuple redirect_tuple = {};

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		redirect_tuple.sip.u6_addr32[3] = tuples.five.dip.u6_addr32[3];
		redirect_tuple.dip.u6_addr32[3] = tuples.five.sip.u6_addr32[3];
	} else {
		__builtin_memcpy(&redirect_tuple.sip, &tuples.five.dip, IPV6_BYTE_LENGTH);
		__builtin_memcpy(&redirect_tuple.dip, &tuples.five.sip, IPV6_BYTE_LENGTH);
	}
	redirect_tuple.l4proto = l4proto;
	struct redirect_entry *redirect_entry = bpf_map_lookup_elem(&redirect_track,
								    &redirect_tuple);

	if (!redirect_entry)
		return TC_ACT_OK;

	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
			    redirect_entry->dmac, sizeof(redirect_entry->dmac), 0);
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
			    redirect_entry->smac, sizeof(redirect_entry->smac), 0);
	__u32 type = redirect_entry->from_wan ? PACKET_HOST : PACKET_OTHERHOST;

	bpf_skb_change_type(skb, type);
	__u64 flags = redirect_entry->from_wan ? BPF_F_INGRESS : 0;

	return bpf_redirect(redirect_entry->ifindex, flags);
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
	struct pid_pname val = {0};
	char buf[MAX_ARG_SCANNER_BUFFER_SIZE] = {0};
	struct task_struct *current = (void *)bpf_get_current_task();
	unsigned long arg_start = BPF_CORE_READ(current, mm, arg_start);
	unsigned long arg_end = BPF_CORE_READ(current, mm, arg_end);

	/*
	 * For string like: /usr/lib/sddm/sddm-helper --socket /tmp/sddm-auth1
	 * We extract "sddm-helper" from it.
	 */
	unsigned long loc, j, last_slash = -1;
#pragma unroll
	for (loc = 0, j = 0; j < MAX_ARG_LEN_TO_PROBE;
			 ++j, loc = ((loc + 1) & (MAX_ARG_SCANNER_BUFFER_SIZE - 1))) {
		// volatile unsigned long k = j; // Cheat to unroll.
		if (unlikely(arg_start + j >= arg_end))
			break;
		if (unlikely(loc == 0)) {
			/// WANRING: Do NOT use bpf_core_read_user_str, it will bring terminator
			/// 0.
			// __builtin_memset(&buf, 0, MAX_ARG_SCANNER_BUFFER_SIZE);
			unsigned long to_read = arg_end - (arg_start + j);

			if (to_read >= MAX_ARG_SCANNER_BUFFER_SIZE)
				to_read = MAX_ARG_SCANNER_BUFFER_SIZE;
			else
				buf[to_read] = 0;
			ret = bpf_core_read_user(&buf, to_read, (const void *)(arg_start + j));
			if (ret) {
				// bpf_printk("failed to read process name.0: [%ld, %ld]", arg_start,
				//            arg_end);
				// bpf_printk("_failed to read process name.0: %ld %ld", j, to_read);
				return ret;
			}
		}
		if (unlikely(buf[loc] == '/'))
			last_slash = j;
		else if (unlikely(buf[loc] == ' ' || buf[loc] == 0))
			break;
	}
	++last_slash;
	unsigned long length_cpy = j - last_slash;

	if (length_cpy > TASK_COMM_LEN)
		length_cpy = TASK_COMM_LEN;
	ret = bpf_core_read_user(&val.pname, length_cpy, (const void *)(arg_start + last_slash));
	if (ret) {
		bpf_printk("failed to read process name.1: %d", ret);
		return ret;
	}
	ret = bpf_core_read(&val.pid, sizeof(val.pid), &current->tgid);
	if (ret) {
		bpf_printk("failed to read pid: %d", ret);
		return ret;
	}
	// bpf_printk("a start_end: %lu %lu", arg_start, arg_end);
	// bpf_printk("b start_end: %lu %lu", arg_start + last_slash, arg_start + j);

	// Update map.
	ret = bpf_map_update_elem(&cookie_pid_map, &cookie, &val, BPF_ANY);
	if (unlikely(ret)) {
		// bpf_printk("setup_mapping_from_sk: failed update map: %d", ret);
		return ret;
	}
	bpf_map_update_elem(&tgid_pname_map, &val.pid, &val.pname, BPF_ANY);

#ifdef __PRINT_SETUP_PROCESS_CONNNECTION
	bpf_printk("setup_mapping: %llu -> %s (%d)", cookie, val.pname, val.pid);
#endif
	return 0;
}

static __always_inline int update_map_elem_by_cookie(const __u64 cookie)
{
	int ret;

	ret = _update_map_elem_by_cookie(cookie);
	if (ret) {
		// Fallback to only write pid to avoid loop due to packets sent by dae.
		struct pid_pname val = {0};

		val.pid = bpf_get_current_pid_tgid() >> 32;
		__u32(*pname)[TASK_COMM_LEN] = bpf_map_lookup_elem(&tgid_pname_map,
								   &val.pid);
		if (pname) {
			__builtin_memcpy(val.pname, *pname, TASK_COMM_LEN);
			ret = 0;
			bpf_printk("fallback [retrieve pname]: %u", val.pid);
		} else {
			bpf_printk("failed [retrieve pname]: %u", val.pid);
		}
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

SEC("sockops")
int local_tcp_sockops(struct bpf_sock_ops *skops)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 pid = BPF_CORE_READ(task, pid);

	/* Only local TCP connection has non-zero pids. */
	if (pid == 0)
		return 0;

	struct tuples_key tuple = {};

	tuple.l4proto = IPPROTO_TCP;
	tuple.sport = bpf_htonl(skops->local_port) >> 16;
	tuple.dport = skops->remote_port >> 16;
	if (skops->family == AF_INET) {
		tuple.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuple.sip.u6_addr32[3] = skops->local_ip4;
		tuple.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuple.dip.u6_addr32[3] = skops->remote_ip4;
	} else if (skops->family == AF_INET6) {
		tuple.sip.u6_addr32[3] = skops->local_ip6[3];
		tuple.sip.u6_addr32[2] = skops->local_ip6[2];
		tuple.sip.u6_addr32[1] = skops->local_ip6[1];
		tuple.sip.u6_addr32[0] = skops->local_ip6[0];
		tuple.dip.u6_addr32[3] = skops->remote_ip6[3];
		tuple.dip.u6_addr32[2] = skops->remote_ip6[2];
		tuple.dip.u6_addr32[1] = skops->remote_ip6[1];
		tuple.dip.u6_addr32[0] = skops->remote_ip6[0];
	} else {
		return 0;
	}

	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // dae sockets
		{
			struct tuples_key rev_tuple = {};

			rev_tuple.l4proto = IPPROTO_TCP;
			rev_tuple.sport = tuple.dport;
			rev_tuple.dport = tuple.sport;
			__builtin_memcpy(&rev_tuple.sip, &tuple.dip, IPV6_BYTE_LENGTH);
			__builtin_memcpy(&rev_tuple.dip, &tuple.sip, IPV6_BYTE_LENGTH);

			struct routing_result *routing_result;

			routing_result = bpf_map_lookup_elem(&routing_tuples_map, &rev_tuple);
			if (!routing_result || !routing_result->pid)
				break;

			if (!bpf_sock_hash_update(skops, &fast_sock, &tuple, BPF_ANY))
				bpf_printk("fast_sock added: %pI4:%lu -> %pI4:%lu",
					   &tuple.sip.u6_addr32[3], bpf_ntohs(tuple.sport),
					   &tuple.dip.u6_addr32[3], bpf_ntohs(tuple.dport));
			break;
		}

	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: // local client sockets
		{
			struct routing_result *routing_result;

			routing_result = bpf_map_lookup_elem(&routing_tuples_map, &tuple);
			if (!routing_result || !routing_result->pid)
				break;

			if (!bpf_sock_hash_update(skops, &fast_sock, &tuple, BPF_ANY))
				bpf_printk("fast_sock added: %pI4:%lu -> %pI4:%lu",
					   &tuple.sip.u6_addr32[3], bpf_ntohs(tuple.sport),
					   &tuple.dip.u6_addr32[3], bpf_ntohs(tuple.dport));
			break;
		}

	default:
		break;
	}

	return 0;
}

SEC("sk_msg/fast_redirect")
int sk_msg_fast_redirect(struct sk_msg_md *msg)
{
	struct tuples_key rev_tuple = {};

	rev_tuple.l4proto = IPPROTO_TCP;
	rev_tuple.sport = msg->remote_port >> 16;
	rev_tuple.dport = bpf_htonl(msg->local_port) >> 16;
	if (msg->family == AF_INET) {
		rev_tuple.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		rev_tuple.sip.u6_addr32[3] = msg->remote_ip4;
		rev_tuple.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		rev_tuple.dip.u6_addr32[3] = msg->local_ip4;
	} else if (msg->family == AF_INET6) {
		rev_tuple.sip.u6_addr32[3] = msg->remote_ip6[3];
		rev_tuple.sip.u6_addr32[2] = msg->remote_ip6[2];
		rev_tuple.sip.u6_addr32[1] = msg->remote_ip6[1];
		rev_tuple.sip.u6_addr32[0] = msg->remote_ip6[0];
		rev_tuple.dip.u6_addr32[3] = msg->local_ip6[3];
		rev_tuple.dip.u6_addr32[2] = msg->local_ip6[2];
		rev_tuple.dip.u6_addr32[1] = msg->local_ip6[1];
		rev_tuple.dip.u6_addr32[0] = msg->local_ip6[0];
	} else {
		return SK_PASS;
	}

	if (bpf_msg_redirect_hash(msg, &fast_sock, &rev_tuple, BPF_F_INGRESS) == SK_PASS)
		bpf_printk("tcp fast redirect: %pI4:%lu -> %pI4:%lu",
			   &rev_tuple.sip.u6_addr32[3], bpf_ntohs(rev_tuple.sport),
			   &rev_tuple.dip.u6_addr32[3], bpf_ntohs(rev_tuple.dport));

	return SK_PASS;
}

SEC("license") const char __license[] = "Dual BSD/GPL";
