// +build ignore
/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

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
// #define __REMOVE_BPF_PRINTK
// #define __UNROLL_ROUTE_LOOP

// #define likely(x) x
// #define unlikely(x) x
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

#define IPV6_BYTE_LENGTH 16
#define TASK_COMM_LEN 16

#define IPV4_CSUM_OFF(eth_h_len) (eth_h_len + offsetof(struct iphdr, check))
#define IPV4_DST_OFF(eth_h_len) (eth_h_len + offsetof(struct iphdr, daddr))
#define IPV4_SRC_OFF(eth_h_len) (eth_h_len + offsetof(struct iphdr, saddr))
#define IPV6_DST_OFF(eth_h_len) (eth_h_len + offsetof(struct ipv6hdr, daddr))
#define IPV6_SRC_OFF(eth_h_len) (eth_h_len + offsetof(struct ipv6hdr, saddr))

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
static const __u32 zero_key = 0;
static const __u32 tproxy_port_key = 1;
static const __u32 one_key = 1;
static const __u32 disable_l4_tx_checksum_key
    __attribute__((unused, deprecated)) = 2;
static const __u32 disable_l4_rx_checksum_key
    __attribute__((unused, deprecated)) = 3;
static const __u32 control_plane_pid_key = 4;
static const __u32 control_plane_nat_direct_key
    __attribute__((unused, deprecated)) = 5;
static const __u32 control_plane_dns_routing_key
    __attribute__((unused, deprecated)) = 6;

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

/// TODO: Remove items from the dst_map by conntrack.
// Dest map:

union ip6 {
  __u8 u6_addr8[16];
  __be16 u6_addr16[8];
  __be32 u6_addr32[4];
  __be64 u6_addr64[2];
};

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
};

struct dst_routing_result {
  __be32 ip[4];
  __be16 port;
  __u16 recognize;
  struct routing_result routing_result;
};

struct tuples {
  union ip6 sip;
  union ip6 dip;
  __u16 sport;
  __u16 dport;
  __u8 l4proto;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key,
         struct ip_port); // As TCP client side [SYN, !ACK],
                          // (source ip, source port, tcp) is
                          // enough for identifier. And UDP client
                          // side does not care it (full-cone).
  __type(value, struct dst_routing_result); // Original target.
  __uint(max_entries, MAX_DST_MAPPING_NUM);
  /// NOTICE: It MUST be pinned, or connection may break.
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_dst_map
    SEC(".maps"); // This map is only for old method (redirect mode in WAN).

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key,
         __u32);                           // tgid
  __type(value, __u32[TASK_COMM_LEN / 4]); // process name.
  __uint(max_entries, MAX_TGID_PNAME_MAPPING_NUM);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} tgid_pname_map
    SEC(".maps"); // This map is only for old method (redirect mode in WAN).

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct tuples);
  __type(value, struct routing_result); // outbound
  __uint(max_entries, MAX_DST_MAPPING_NUM);
  /// NOTICE: It MUST be pinned.
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} routing_tuples_map SEC(".maps");

// Params:
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_PARAM_LEN);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} param_map SEC(".maps");

// Link to type:
#define LinkType_None 0
#define LinkType_Ethernet 1
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);   // ifindex
  __type(value, __u32); // LinkType
  __uint(max_entries, MAX_INTERFACE_NUM);
  /// NOTICE: No persistence.
  // __uint(pinning, LIBBPF_PIN_BY_NAME);
} linktype_map SEC(".maps");

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
 Rule is like as following:

 domain(geosite:cn, suffix: google.com) && l4proto(tcp) -> my_group

 pseudocode: domain(geosite:cn || suffix:google.com) && l4proto(tcp) -> my_group

 A match_set can be: IP set geosite:cn, suffix google.com, tcp proto
 */
struct match_set {
  union {
    __u8 __value[16]; // Placeholder for bpf2go.

    __u32 index;
    struct port_range port_range;
    enum L4ProtoType l4proto_type;
    enum IpVersionType ip_version;
    __u32 pname[TASK_COMM_LEN / 4];
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

static void __always_inline
get_tuples(const struct __sk_buff *skb, struct tuples *tuples,
           const struct iphdr *iph, const struct ipv6hdr *ipv6h,
           const struct tcphdr *tcph, const struct udphdr *udph, __u8 l4proto) {
  __builtin_memset(tuples, 0, sizeof(*tuples));
  tuples->l4proto = l4proto;
  if (skb->protocol == bpf_htons(ETH_P_IP)) {
    tuples->sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
    tuples->sip.u6_addr32[3] = iph->saddr;

    tuples->dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
    tuples->dip.u6_addr32[3] = iph->daddr;

  } else {
    __builtin_memcpy(&tuples->dip, &ipv6h->daddr, IPV6_BYTE_LENGTH);
    __builtin_memcpy(&tuples->sip, &ipv6h->saddr, IPV6_BYTE_LENGTH);
  }
  if (l4proto == IPPROTO_TCP) {
    tuples->sport = tcph->source;
    tuples->dport = tcph->dest;
  } else {
    tuples->sport = udph->source;
    tuples->dport = udph->dest;
  }
}

static __always_inline bool equal16(const __be32 x[4], const __be32 y[4]) {
#if __clang_major__ >= 10
  return ((__be64 *)x)[0] == ((__be64 *)y)[0] &&
         ((__be64 *)x)[1] == ((__be64 *)y)[1];

  // return x[0] == y[0] && x[1] == y[1] && x[2] == y[2] && x[3] == y[3];
#else
  return __builtin_bcmp(x, y, IPV6_BYTE_LENGTH) == 0;
#endif
}

static __always_inline __u32 l4_checksum_rel_off(__u8 proto) {
  switch (proto) {
  case IPPROTO_TCP:
    return offsetof(struct tcphdr, check);

  case IPPROTO_UDP:
    return offsetof(struct udphdr, check);
  }
  return 0;
}

static __always_inline __u32 l4_checksum_off(__u32 eth_h_len, __u8 proto,
                                             __u8 ihl) {
  return eth_h_len + ihl * 4 + l4_checksum_rel_off(proto);
}

static __always_inline int disable_l4_checksum(struct __sk_buff *skb,
                                               __u32 eth_h_len, __u8 l4proto,
                                               __u8 ihl) {
  __u32 l4_cksm_off = l4_checksum_off(eth_h_len, l4proto, ihl);
  // Set checksum zero.
  __sum16 bak_cksm = 0;
  return bpf_skb_store_bytes(skb, l4_cksm_off, &bak_cksm, sizeof(bak_cksm), 0);
}

static __always_inline int rewrite_ip(struct __sk_buff *skb, __u32 eth_h_len,
                                      __u8 proto, __u8 ihl, __be32 old_ip[4],
                                      __be32 new_ip[4], bool is_dest,
                                      bool disable_l4_checksum) {
  // Nothing to do.
  if (equal16(old_ip, new_ip)) {
    return 0;
  }
  // bpf_printk("%pI6->%pI6", old_ip, new_ip);

  __u32 l4_cksm_off = l4_checksum_off(eth_h_len, proto, ihl);
  int ret;
  // BPF_F_PSEUDO_HDR indicates the part we want to modify is part of the
  // pseudo header.
  __u32 l4flags = BPF_F_PSEUDO_HDR;
  if (proto == IPPROTO_UDP) {
    l4flags |= BPF_F_MARK_MANGLED_0;
  }

  if (skb->protocol == bpf_htons(ETH_P_IP)) {

    __be32 _old_ip = old_ip[3];
    __be32 _new_ip = new_ip[3];

    int ret;

    if (!disable_l4_checksum) {
      if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, _old_ip, _new_ip,
                                     l4flags | sizeof(_new_ip)))) {
        bpf_printk("bpf_l4_csum_replace: %d", ret);
        return ret;
      }
    }

    if ((ret = bpf_l3_csum_replace(skb, IPV4_CSUM_OFF(eth_h_len), _old_ip,
                                   _new_ip, sizeof(_new_ip)))) {
      return ret;
    }
    // bpf_printk("%pI4 -> %pI4", &_old_ip, &_new_ip);

    ret = bpf_skb_store_bytes(
        skb, is_dest ? IPV4_DST_OFF(eth_h_len) : IPV4_SRC_OFF(eth_h_len),
        &_new_ip, sizeof(_new_ip), 0);
    if (ret) {
      bpf_printk("bpf_skb_store_bytes: %d", ret);
      return ret;
    }
  } else {

    if (!disable_l4_checksum) {
      __s64 cksm =
          bpf_csum_diff(old_ip, IPV6_BYTE_LENGTH, new_ip, IPV6_BYTE_LENGTH, 0);
      if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, 0, cksm, l4flags))) {
        bpf_printk("bpf_l4_csum_replace: %d", ret);
        return ret;
      }
    }

    // bpf_printk("%pI6 -> %pI6", old_ip, new_ip);

    ret = bpf_skb_store_bytes(
        skb, is_dest ? IPV6_DST_OFF(eth_h_len) : IPV6_SRC_OFF(eth_h_len),
        new_ip, IPV6_BYTE_LENGTH, 0);
    if (ret) {
      bpf_printk("bpf_skb_store_bytes: %d", ret);
      return ret;
    }
  }

  return 0;
}

static __always_inline int rewrite_port(struct __sk_buff *skb, __u32 eth_h_len,
                                        __u8 proto, __u8 ihl, __be16 old_port,
                                        __be16 new_port, bool is_dest,
                                        bool disable_l4_checksum) {
  // Nothing to do.
  if (old_port == new_port) {
    return 0;
  }

  __u32 cksm_off = l4_checksum_off(eth_h_len, proto, ihl),
        port_off = eth_h_len + ihl * 4;
  if (!cksm_off) {
    return -EINVAL;
  }
  __u32 l4flags = 0;
  switch (proto) {
  case IPPROTO_TCP:
    if (is_dest) {
      port_off += offsetof(struct tcphdr, dest);
    } else {
      port_off += offsetof(struct tcphdr, source);
    }
    break;

  case IPPROTO_UDP:
    if (is_dest) {
      port_off += offsetof(struct udphdr, dest);
    } else {
      port_off += offsetof(struct udphdr, source);
    }
    l4flags |= BPF_F_MARK_MANGLED_0;
    break;

  default:
    return -EINVAL;
  }

  // bpf_printk("%u -> %u", bpf_ntohs(old_port), bpf_ntohs(new_port));

  int ret;

  if (!disable_l4_checksum) {
    if ((ret = bpf_l4_csum_replace(skb, cksm_off, old_port, new_port,
                                   l4flags | sizeof(new_port)))) {
      bpf_printk("bpf_l4_csum_replace: %d", ret);
      return ret;
    }
  }

  if ((ret = bpf_skb_store_bytes(skb, port_off, &new_port, sizeof(new_port),
                                 0))) {
    return ret;
  }
  return 0;
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
      if ((ret = bpf_skb_load_bytes(skb, offset, icmp6h, hdr_length))) {
        bpf_printk("not a valid IPv6 packet");
        return -EFAULT;
      }
      return 0;

    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
      if ((ret = bpf_skb_load_bytes(skb, offset + 1, &hdr_length,
                                    sizeof(hdr_length)))) {
        bpf_printk("not a valid IPv6 packet");
        return -EFAULT;
      }
    special_n1:
      if ((ret = bpf_skb_load_bytes(skb, offset, &nexthdr, sizeof(nexthdr)))) {
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
        if ((ret = bpf_skb_load_bytes(skb, offset, tcph,
                                      sizeof(struct tcphdr)))) {
          bpf_printk("not a valid IPv6 packet");
          return -EFAULT;
        }
      } else if (hdr == IPPROTO_UDP) {
        // Upper layer;
        if ((ret = bpf_skb_load_bytes(skb, offset, udph,
                                      sizeof(struct udphdr)))) {
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
parse_transport(const struct __sk_buff *skb, __u32 eth_h_len,
                struct ethhdr *ethh, struct iphdr *iph, struct ipv6hdr *ipv6h,
                struct icmp6hdr *icmp6h, struct tcphdr *tcph,
                struct udphdr *udph, __u8 *ihl, __u8 *l4proto) {

  __u32 offset = 0;
  int ret;
  if (eth_h_len == ETH_HLEN) {
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

    if ((ret = bpf_skb_load_bytes(skb, offset, iph, sizeof(struct iphdr)))) {
      return -EFAULT;
    }
    // Skip ipv4hdr and options for next hdr.
    offset += iph->ihl * 4;

    // We only process TCP and UDP traffic.
    *l4proto = iph->protocol;
    switch (iph->protocol) {
    case IPPROTO_TCP: {
      if ((ret =
               bpf_skb_load_bytes(skb, offset, tcph, sizeof(struct tcphdr)))) {
        // Not a complete tcphdr.
        return -EFAULT;
      }
    } break;
    case IPPROTO_UDP: {
      if ((ret =
               bpf_skb_load_bytes(skb, offset, tcph, sizeof(struct tcphdr)))) {
        // Not a complete tcphdr.
        return -EFAULT;
      }
    } break;
    default:
      /// EXPECTED: Maybe ICMP, MPLS, etc.
      // bpf_printk("IP but not supported packet: protocol is %u",
      // iph->protocol);
      return 1;
    }
    *ihl = iph->ihl;
    return 0;
  } else if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {

    if ((ret =
             bpf_skb_load_bytes(skb, offset, ipv6h, sizeof(struct ipv6hdr)))) {
      bpf_printk("not a valid IPv6 packet");
      return -EFAULT;
    }

    offset += sizeof(struct ipv6hdr);

    return handle_ipv6_extensions(skb, offset, ipv6h->nexthdr, icmp6h, tcph,
                                  udph, ihl, l4proto);
  } else {
    bpf_printk("unknown link proto: %u", bpf_ntohl(skb->protocol));
    return 1;
  }
}

static __always_inline int adjust_udp_len(struct __sk_buff *skb,
                                          __u32 eth_h_len, __u16 oldlen,
                                          __u32 ihl, __u16 len_diff,
                                          bool disable_l4_checksum) {
  if (unlikely(!len_diff)) {
    return 0;
  }

  // Boundary check.
  if (len_diff > 0) {
    if (unlikely(bpf_ntohs(oldlen) + len_diff < len_diff)) { // overflow
      bpf_printk("udp length overflow");
      return -EINVAL;
    }
  } else {
    if (unlikely((__s32)bpf_ntohs(oldlen) + len_diff < 0)) { // not enough
      bpf_printk("udp length not enough");
      return -EINVAL;
    }
  }
  __be16 newlen = bpf_htons(bpf_ntohs(oldlen) + len_diff);

  // Calculate checksum and store the new value.
  int ret;
  __u32 udp_csum_off = l4_checksum_off(eth_h_len, IPPROTO_UDP, ihl);

  if (!disable_l4_checksum) { // replace twice because len exists both pseudo
                              // hdr and hdr.
    if ((ret = bpf_l4_csum_replace(
             skb, udp_csum_off, oldlen, newlen,
             sizeof(oldlen) | BPF_F_PSEUDO_HDR | // udp len is in the pseudo hdr
                 BPF_F_MARK_MANGLED_0))) {
      bpf_printk("bpf_l4_csum_replace newudplen: %d", ret);
      return ret;
    }
    if ((ret = bpf_l4_csum_replace(skb, udp_csum_off, oldlen, newlen,
                                   sizeof(oldlen) | BPF_F_MARK_MANGLED_0))) {
      bpf_printk("bpf_l4_csum_replace newudplen: %d", ret);
      return ret;
    }
  }

  if ((ret = bpf_skb_store_bytes(
           skb, eth_h_len + ihl * 4 + offsetof(struct udphdr, len), &newlen,
           sizeof(oldlen), 0))) {
    bpf_printk("bpf_skb_store_bytes newudplen: %d", ret);
    return ret;
  }
  return 0;
}

static __always_inline int adjust_ipv4_len(struct __sk_buff *skb,
                                           __u32 eth_h_len, __u16 oldlen,
                                           __u16 len_diff) {
  if (unlikely(!len_diff)) {
    return 0;
  }

  // Boundary check.
  if (len_diff > 0) {
    if (unlikely(bpf_ntohs(oldlen) + len_diff < len_diff)) { // overflow
      bpf_printk("ip length overflow");
      return -EINVAL;
    }
  } else {
    if (unlikely((__s32)bpf_ntohs(oldlen) + len_diff < 0)) { // not enough
      bpf_printk("ip length not enough");
      return -EINVAL;
    }
  }
  __be16 newlen = bpf_htons(bpf_ntohs(oldlen) + len_diff);

  // Calculate checksum and store the new value.
  int ret;
  if ((ret = bpf_l3_csum_replace(skb, IPV4_CSUM_OFF(eth_h_len), oldlen, newlen,
                                 sizeof(oldlen)))) {
    bpf_printk("bpf_l3_csum_replace newudplen: %d", ret);
    return ret;
  }
  if ((ret =
           bpf_skb_store_bytes(skb, eth_h_len + offsetof(struct iphdr, tot_len),
                               &newlen, sizeof(oldlen), 0))) {
    bpf_printk("bpf_skb_store_bytes newiplen: %d", ret);
    return ret;
  }
  return 0;
}

static __always_inline int encap_after_udp_hdr(struct __sk_buff *skb,
                                               __u32 eth_h_len, __u8 ihl,
                                               __be16 iphdr_tot_len,
                                               void *newhdr, __u32 newhdrlen,
                                               bool disable_l4_checksum) {
  if (unlikely(newhdrlen % 4 != 0)) {
    bpf_printk("encap_after_udp_hdr: unexpected newhdrlen value %u :must "
               "be a multiple of 4",
               newhdrlen);
    return -EINVAL;
  }

  int ret = 0;
  long ip_off = eth_h_len;
  // Calculate offsets using add instead of subtract to avoid verifier problems.
  long ipp_len = ihl * 4;
  long udp_payload_off = ip_off + ipp_len + sizeof(struct udphdr);

  // Backup for further use.
  struct udphdr reserved_udphdr;
  if ((ret = bpf_skb_load_bytes(skb, ip_off + ipp_len, &reserved_udphdr,
                                sizeof(reserved_udphdr)))) {
    bpf_printk("bpf_skb_load_bytes: %d", ret);
    return ret;
  }
  // Add room for new udp payload header.
  if ((ret = bpf_skb_adjust_room(skb, newhdrlen, BPF_ADJ_ROOM_NET,
                                 BPF_F_ADJ_ROOM_NO_CSUM_RESET))) {
    bpf_printk("UDP ADJUST ROOM(encap): %d", ret);
    return ret;
  }
  // Move the new room to the front of the UDP payload.
  if ((ret = bpf_skb_store_bytes(skb, ip_off + ipp_len, &reserved_udphdr,
                                 sizeof(reserved_udphdr), 0))) {
    bpf_printk("bpf_skb_store_bytes reserved_udphdr: %d", ret);
    return ret;
  }

  // Rewrite ip len.
  if (skb->protocol == bpf_htons(ETH_P_IP)) {
    if ((ret = adjust_ipv4_len(skb, eth_h_len, iphdr_tot_len, newhdrlen))) {
      bpf_printk("adjust_ip_len: %d", ret);
      return ret;
    }
  }

  // Rewrite udp len.
  if ((ret = adjust_udp_len(skb, eth_h_len, reserved_udphdr.len, ihl, newhdrlen,
                            disable_l4_checksum))) {
    bpf_printk("adjust_udp_len: %d", ret);
    return ret;
  }

  // Rewrite udp payload.
  if (!disable_l4_checksum) {
    __u32 l4_cksm_off = l4_checksum_off(eth_h_len, IPPROTO_UDP, ihl);
    __s64 cksm = bpf_csum_diff(NULL, 0, newhdr, newhdrlen, 0);
    if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, 0, cksm,
                                   BPF_F_MARK_MANGLED_0))) {
      bpf_printk("bpf_l4_csum_replace 2: %d", ret);
      return ret;
    }
  }
  if ((ret = bpf_skb_store_bytes(skb, udp_payload_off, newhdr, newhdrlen, 0))) {
    bpf_printk("bpf_skb_store_bytes 2: %d", ret);
    return ret;
  }
  return 0;
}

static __always_inline int
decap_after_udp_hdr(struct __sk_buff *skb, __u32 eth_h_len, __u8 ihl,
                    __be16 ipv4hdr_tot_len, void *to, __u32 decap_hdrlen,
                    bool (*prevent_pop)(void *to), bool disable_l4_checksum) {
  if (unlikely(decap_hdrlen % 4 != 0)) {
    bpf_printk("encap_after_udp_hdr: unexpected decap_hdrlen value %u :must "
               "be a multiple of 4",
               decap_hdrlen);
    return -EINVAL;
  }
  int ret = 0;
  long ip_off = eth_h_len;
  // Calculate offsets using add instead of subtract to avoid verifier problems.
  long ipp_len = ihl * 4;

  // Must check lower boundary for packet offset (and set the type of the
  // variables to signed long).
  if (skb->data + ip_off + ipp_len > skb->data_end) {
    return -EINVAL;
  }

  // Backup for further use.
  struct udphdr reserved_udphdr;
  if ((ret = bpf_skb_load_bytes(skb, ip_off + ipp_len, &reserved_udphdr,
                                sizeof(struct udphdr)))) {
    bpf_printk("bpf_skb_load_bytes: %d", ret);
    return ret;
  }

  // Load the hdr to decap.
  if ((ret = bpf_skb_load_bytes(skb, ip_off + ipp_len + sizeof(struct udphdr),
                                to, decap_hdrlen))) {
    bpf_printk("bpf_skb_load_bytes decap_hdr: %d", ret);
    return ret;
  }

  // Move the udphdr to the front of the real UDP payload.
  if ((ret =
           bpf_skb_store_bytes(skb, ip_off + ipp_len + decap_hdrlen,
                               &reserved_udphdr, sizeof(reserved_udphdr), 0))) {
    bpf_printk("bpf_skb_store_bytes reserved_udphdr: %d", ret);
    return ret;
  }

  if (prevent_pop == NULL || !prevent_pop(to)) {
    // Adjust room to decap the header.
    if ((ret = bpf_skb_adjust_room(skb, -decap_hdrlen, BPF_ADJ_ROOM_NET,
                                   BPF_F_ADJ_ROOM_NO_CSUM_RESET))) {
      bpf_printk("UDP ADJUST ROOM(decap): %d", ret);
      return ret;
    }

    // Rewrite ip len.
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
      if ((ret = adjust_ipv4_len(skb, eth_h_len, ipv4hdr_tot_len,
                                 -decap_hdrlen))) {
        bpf_printk("adjust_ip_len: %d", ret);
        return ret;
      }
    }

    // Rewrite udp len.
    if ((ret = adjust_udp_len(skb, eth_h_len, reserved_udphdr.len, ihl,
                              -decap_hdrlen, disable_l4_checksum))) {
      bpf_printk("adjust_udp_len: %d", ret);
      return ret;
    }

    if (!disable_l4_checksum) {
      // Rewrite udp checksum.
      __u32 udp_csum_off = l4_checksum_off(eth_h_len, IPPROTO_UDP, ihl);
      __s64 cksm = bpf_csum_diff(to, decap_hdrlen, 0, 0, 0);
      if ((ret = bpf_l4_csum_replace(skb, udp_csum_off, 0, cksm,
                                     BPF_F_MARK_MANGLED_0))) {
        bpf_printk("bpf_l4_csum_replace 2: %d", ret);
        return ret;
      }
    }
  }
  return 0;
}

// Do not use __always_inline here because this function is too heavy.
// low -> high: outbound(8b) mark(32b) unused(23b) sign(1b)
static __s64 __attribute__((noinline))
route(const __u32 flag[6], const void *l4hdr, const __be32 saddr[4],
      const __be32 daddr[4], const __be32 mac[4]) {
#define _l4proto_type flag[0]
#define _ipversion_type flag[1]
#define _pname &flag[2]
#define _is_wan flag[2]

  int ret;
  struct lpm_key lpm_key_instance, *lpm_key;
  __u32 key = MatchType_L4Proto;
  __u16 h_dport;
  __u16 h_sport;

  /// TODO: BPF_MAP_UPDATE_BATCH ?
  if (unlikely((ret = bpf_map_update_elem(&l4proto_ipversion_map, &key,
                                          &_l4proto_type, BPF_ANY)))) {
    return ret;
  };
  key = MatchType_IpVersion;
  if (unlikely((ret = bpf_map_update_elem(&l4proto_ipversion_map, &key,
                                          &_ipversion_type, BPF_ANY)))) {
    return ret;
  };

  // Variables for further use.
  if (_l4proto_type == L4ProtoType_TCP) {
    h_dport = bpf_ntohs(((struct tcphdr *)l4hdr)->dest);
    h_sport = bpf_ntohs(((struct tcphdr *)l4hdr)->source);
  } else {
    h_dport = bpf_ntohs(((struct udphdr *)l4hdr)->dest);
    h_sport = bpf_ntohs(((struct udphdr *)l4hdr)->source);
  }

  key = MatchType_SourcePort;
  if (unlikely(
          (ret = bpf_map_update_elem(&h_port_map, &key, &h_sport, BPF_ANY)))) {
    return ret;
  };
  key = MatchType_Port;
  if (unlikely(
          (ret = bpf_map_update_elem(&h_port_map, &key, &h_dport, BPF_ANY)))) {
    return ret;
  };

  lpm_key_instance.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
  __builtin_memcpy(lpm_key_instance.data, daddr, IPV6_BYTE_LENGTH);
  key = MatchType_IpSet;
  if (unlikely((ret = bpf_map_update_elem(&lpm_key_map, &key, &lpm_key_instance,
                                          BPF_ANY)))) {
    return ret;
  };
  __builtin_memcpy(lpm_key_instance.data, saddr, IPV6_BYTE_LENGTH);
  key = MatchType_SourceIpSet;
  if (unlikely((ret = bpf_map_update_elem(&lpm_key_map, &key, &lpm_key_instance,
                                          BPF_ANY)))) {
    return ret;
  };
  __builtin_memcpy(lpm_key_instance.data, mac, IPV6_BYTE_LENGTH);
  key = MatchType_Mac;
  if (unlikely((ret = bpf_map_update_elem(&lpm_key_map, &key, &lpm_key_instance,
                                          BPF_ANY)))) {
    return ret;
  };

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
    if (unlikely(!match_set)) {
      return -EFAULT;
    }
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
    if ((lpm_key = bpf_map_lookup_elem(&lpm_key_map, &key))) {
#ifdef __DEBUG_ROUTING
      bpf_printk(
          "CHECK: lpm_key_map, match_set->type: %u, not: %d, outbound: %u",
          match_set->type, match_set->not, match_set->outbound);
      bpf_printk("\tip: %pI6", lpm_key->data);
#endif
      lpm = bpf_map_lookup_elem(&lpm_array_map, &match_set->index);
      if (unlikely(!lpm)) {
        return -EFAULT;
      }
      if (bpf_map_lookup_elem(lpm, lpm_key)) {
        // match_set hits.
        isdns_must_goodsubrule_badrule |= 0b10;
      }
    } else if ((p_u16 = bpf_map_lookup_elem(&h_port_map, &key))) {
#ifdef __DEBUG_ROUTING
      bpf_printk(
          "CHECK: h_port_map, match_set->type: %u, not: %d, outbound: %u",
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
      bpf_printk("CHECK: l4proto_ipversion_map, match_set->type: %u, not: %d, "
                 "outbound: %u",
                 match_set->type, match_set->not, match_set->outbound);
#endif
      if (*p_u32 & *(__u32 *)&match_set->__value) {
        isdns_must_goodsubrule_badrule |= 0b10;
      }
    } else {
      switch (key) {
      case MatchType_DomainSet:
#ifdef __DEBUG_ROUTING
        bpf_printk("CHECK: domain, match_set->type: %u, not: %d, "
                   "outbound: %u",
                   match_set->type, match_set->not, match_set->outbound);
#endif

        // Get domain routing bitmap.
        domain_routing = bpf_map_lookup_elem(&domain_routing_map, daddr);

        // We use key instead of k to pass checker.
        if (domain_routing &&
            (domain_routing->bitmap[i / 32] >> (i % 32)) & 1) {
          isdns_must_goodsubrule_badrule |= 0b10;
        }
        break;
      case MatchType_ProcessName:
        if (_is_wan && equal16(match_set->pname, _pname)) {
          isdns_must_goodsubrule_badrule |= 0b10;
        }
        break;
      case MatchType_Fallback:
#ifdef __DEBUG_ROUTING
        bpf_printk("CHECK: hit fallback");
#endif
        isdns_must_goodsubrule_badrule |= 0b10;
        break;
      default:
#ifdef __DEBUG_ROUTING
        bpf_printk("CHECK: <unknown>, match_set->type: %u, not: %d, "
                   "outbound: %u",
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

      if ((isdns_must_goodsubrule_badrule & 0b10) > 0 == match_set->not ) {
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
                   match_set->type, match_set->not );
#endif

        // DNS requests should routed by control plane if outbound is not
        // must_direct.

        if (unlikely(match_set->outbound == OUTBOUND_MUST_RULES)) {
          isdns_must_goodsubrule_badrule |= 0b100;
        } else {
          if (isdns_must_goodsubrule_badrule & 0b100) {
            match_set->must = true;
          }
          if (!match_set->must && (isdns_must_goodsubrule_badrule & 0b1000)) {
            return (__s64)OUTBOUND_CONTROL_PLANE_ROUTING |
                   ((__s64)match_set->mark << 8) |
                   ((__s64)match_set->must << 40);
          } else {
            return (__s64)match_set->outbound | ((__s64)match_set->mark << 8) |
                   ((__s64)match_set->must << 40);
          }
        }
      }
      isdns_must_goodsubrule_badrule &= ~0b1;
    }
  }
  bpf_printk("No match_set hits. Did coder forget to sync "
             "common/consts/ebpf.go with enum MatchType?");
  return -EPERM;
#undef _l4proto_type
#undef _ipversion_type
#undef _pname
#undef _is_wan
}

static bool __always_inline is_not_to_lan(void *_ori_src) {
  struct dst_routing_result *ori_src = _ori_src;
  return ori_src->routing_result.outbound == IS_WAN;
}

static __always_inline int get_eth_h_len(__u32 ifindex, __u32 *eth_h_len) {
  __u32 *link_type = bpf_map_lookup_elem(&linktype_map, &ifindex);
  if (!link_type) {
    return -EIO;
  }
  switch (*link_type) {
  case LinkType_Ethernet: {
    *eth_h_len = ETH_HLEN;
  } break;
  case LinkType_None: {
    *eth_h_len = 0;
  } break;
  default:
    return -EINVAL;
  }
  return 0;
}

// SNAT for UDP packet.
SEC("tc/egress")
int tproxy_lan_egress(struct __sk_buff *skb) {
  if (skb->ingress_ifindex != NOWHERE_IFINDEX) {
    return TC_ACT_PIPE;
  }
  struct ethhdr ethh;
  struct iphdr iph;
  struct ipv6hdr ipv6h;
  struct icmp6hdr icmp6h;
  struct tcphdr tcph;
  struct udphdr udph;
  __u8 ihl;
  __u8 l4proto;
  __u32 eth_h_len;
  if (get_eth_h_len(skb->ifindex, &eth_h_len)) {
    return TC_ACT_OK;
  }
  int ret = parse_transport(skb, eth_h_len, &ethh, &iph, &ipv6h, &icmp6h, &tcph,
                            &udph, &ihl, &l4proto);
  if (ret) {
    bpf_printk("parse_transport: %d", ret);
    return TC_ACT_OK;
  }
  switch (l4proto) {
  case IPPROTO_ICMPV6:
    if (icmp6h.icmp6_type == 137) {
      // REDIRECT (NDP)
      return TC_ACT_SHOT;
    }
    return TC_ACT_PIPE;
  case IPPROTO_UDP:
    break;
  default:
    return TC_ACT_PIPE;
  }

  __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
  if (!tproxy_port) {
    return TC_ACT_PIPE;
  }
  struct tuples tuples;
  get_tuples(skb, &tuples, &iph, &ipv6h, &tcph, &udph, l4proto);
  if (*tproxy_port != tuples.sport) {
    return TC_ACT_PIPE;
  }

  struct dst_routing_result ori_src;
  if ((ret = decap_after_udp_hdr(
           skb, eth_h_len, ihl,
           skb->protocol == bpf_htons(ETH_P_IP) ? iph.tot_len : 0, &ori_src,
           sizeof(ori_src), is_not_to_lan, true))) {
    return TC_ACT_SHOT;
  }
  if (is_not_to_lan(&ori_src)) {
    return TC_ACT_PIPE;
  }
  if ((ret = rewrite_ip(skb, eth_h_len, l4proto, ihl, tuples.sip.u6_addr32,
                        ori_src.ip, false, true))) {
    return TC_ACT_SHOT;
  }
  if ((ret = rewrite_port(skb, eth_h_len, l4proto, ihl, tuples.sport,
                          ori_src.port, false, true))) {
    return TC_ACT_SHOT;
  }
  disable_l4_checksum(skb, eth_h_len, l4proto, ihl);
  // bpf_printk("from %pI6 to %pI6", tuples.sip, ori_src.ip);
  // bpf_printk("from %u to %u", bpf_ntohs(tuples.sport),
  //            bpf_ntohs(ori_src.port));
  return TC_ACT_OK;
}

SEC("tc/ingress")
int tproxy_lan_ingress(struct __sk_buff *skb) {
  struct ethhdr ethh;
  struct iphdr iph;
  struct ipv6hdr ipv6h;
  struct icmp6hdr icmp6h;
  struct tcphdr tcph;
  struct udphdr udph;
  __u8 ihl;
  __u8 l4proto;
  __u32 eth_h_len;
  if (get_eth_h_len(skb->ifindex, &eth_h_len)) {
    return TC_ACT_OK;
  }
  int ret = parse_transport(skb, eth_h_len, &ethh, &iph, &ipv6h, &icmp6h, &tcph,
                            &udph, &ihl, &l4proto);
  if (ret) {
    bpf_printk("parse_transport: %d", ret);
    return TC_ACT_OK;
  }
  if (l4proto == IPPROTO_ICMPV6) {
    return TC_ACT_OK;
  }

  // Prepare five tuples.
  struct tuples tuples;
  get_tuples(skb, &tuples, &iph, &ipv6h, &tcph, &udph, l4proto);

  /**
  ip rule add fwmark 0x8000000/0x8000000 table 2023
  ip route add local default dev lo table 2023
  ip -6 rule add fwmark 0x8000000/0x8000000 table 2023
  ip -6 route add local default dev lo table 2023

  ip rule del fwmark 0x8000000/0x8000000 table 2023
  ip route del local default dev lo table 2023
  ip -6 rule del fwmark 0x8000000/0x8000000 table 2023
  ip -6 route del local default dev lo table 2023
  */
  // Socket lookup and assign skb to existing socket connection.
  struct bpf_sock_tuple tuple = {0};
  __u32 tuple_size;
  struct bpf_sock *sk;
  bool is_old_conn = false;
  __u32 flag[6];
  void *l4hdr;

  if (skb->protocol == bpf_htons(ETH_P_IP)) {
    tuple.ipv4.daddr = tuples.dip.u6_addr32[3];
    tuple.ipv4.saddr = tuples.sip.u6_addr32[3];
    tuple.ipv4.dport = tuples.dport;
    tuple.ipv4.sport = tuples.sport;
    tuple_size = sizeof(tuple.ipv4);
  } else {
    __builtin_memcpy(tuple.ipv6.daddr, &tuples.dip, IPV6_BYTE_LENGTH);
    __builtin_memcpy(tuple.ipv6.saddr, &tuples.sip, IPV6_BYTE_LENGTH);
    tuple.ipv6.dport = tuples.dport;
    tuple.ipv6.sport = tuples.sport;
    tuple_size = sizeof(tuple.ipv6);
  }

  if (l4proto == IPPROTO_TCP) {
    // TCP.
    if (tcph.syn && !tcph.ack) {
      goto new_connection;
    }

    sk = bpf_skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);
    if (sk) {
      if (tuples.dport == bpf_ntohs(445)) {
        // samba. It is safe because the smb port cannot be customized.
        goto sk_accept;
      }
      if (sk->state != BPF_TCP_LISTEN) {
        is_old_conn = true;
        goto assign;
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
  if (skb->protocol == bpf_htons(ETH_P_IP)) {
    flag[1] = IpVersionType_4;
  } else {
    flag[1] = IpVersionType_6;
  }
  __be32 mac[4] = {
      0,
      0,
      bpf_htonl((ethh.h_source[0] << 8) + (ethh.h_source[1])),
      bpf_htonl((ethh.h_source[2] << 24) + (ethh.h_source[3] << 16) +
                (ethh.h_source[4] << 8) + (ethh.h_source[5])),
  };
  __s64 s64_ret;
  if ((s64_ret = route(flag, l4hdr, tuples.sip.u6_addr32, tuples.dip.u6_addr32,
                       mac)) < 0) {
    bpf_printk("shot routing: %d", s64_ret);
    return TC_ACT_SHOT;
  }
  struct routing_result routing_result = {0};
  routing_result.outbound = s64_ret;
  routing_result.mark = s64_ret >> 8;
  routing_result.must = (s64_ret >> 40) & 1;
  __builtin_memcpy(routing_result.mac, ethh.h_source,
                   sizeof(routing_result.mac));
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
  if ((ret = bpf_map_update_elem(&routing_tuples_map, &tuples, &routing_result,
                                 BPF_ANY))) {
    bpf_printk("shot save routing result: %d", ret);
    return TC_ACT_SHOT;
  }
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
  if (l4proto == IPPROTO_TCP) {
    bpf_printk("tcp(lan): outbound: %u, target: %pI6:%u", ret,
               tuples.dip.u6_addr32, bpf_ntohs(tuples.dport));
  } else {
    bpf_printk("udp(lan): outbound: %u, target: %pI6:%u",
               routing_result.outbound, tuples.dip.u6_addr32,
               bpf_ntohs(tuples.dport));
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
      !(l4proto == IPPROTO_UDP && tuples.dport == bpf_htons(53))) {
    // Outbound is not alive. Dns is an exception.
    goto block;
  }

  // Assign to control plane.

  if (l4proto == IPPROTO_TCP) {
    // TCP.
    sk = bpf_map_lookup_elem(&listen_socket_map, &zero_key);
    if (!sk || sk->state != BPF_TCP_LISTEN) {
      bpf_printk("accpet tcp tproxy not listen");
      goto sk_accept;
    }
  } else {
    // UDP.

    sk = bpf_map_lookup_elem(&listen_socket_map, &one_key);
    if (!sk) {
      bpf_printk("accpet udp tproxy not listen");
      goto sk_accept;
    }
  }

assign:
  skb->mark = TPROXY_MARK;
  ret = bpf_sk_assign(skb, sk, 0);
  bpf_sk_release(sk);
  if (ret) {
    if (is_old_conn && ret == -ESOCKTNOSUPPORT) {
      bpf_printk("bpf_sk_assign: %d, perhaps you have other TPROXY programs "
                 "(such as v2ray) running?",
                 ret);
    } else {
      bpf_printk("bpf_sk_assign: %d", ret);
    }
    return TC_ACT_SHOT;
  }
  return TC_ACT_OK;

sk_accept:
  if (sk) {
    bpf_sk_release(sk);
  }

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
    __u32 *pid_tproxy;
    if (!(pid_tproxy =
              bpf_map_lookup_elem(&param_map, &control_plane_pid_key))) {
      bpf_printk("control_plane_pid is not set.");
      return false;
    }
    return pid_pname->pid == *pid_tproxy;
  } else {
    if (p) {
      *p = NULL;
    }
    if ((skb->mark & 0x100) == 0x100) {
      bpf_printk("No pid_pname found. But it should not happen");
      /*
      if (l4proto == IPPROTO_TCP) {
        if (tcph.syn && !tcph.ack) {
          bpf_printk("No pid_pname found. But it should not happen: local:%u "
                     "(%u)[%llu]",
                     bpf_ntohs(sport), l4proto, cookie);
        } else {
          bpf_printk("No pid_pname found. But it should not happen: (Old "
                     "Connection): local:%u "
                     "(%u)[%llu]",
                     bpf_ntohs(sport), l4proto, cookie);
        }
      } else {
        bpf_printk("No pid_pname found. But it should not happen: local:%u "
                   "(%u)[%llu]",
                   bpf_ntohs(sport), l4proto, cookie);
      }
      */
      return true;
    }
    return false;
  }
}

__u8 special_mac_to_tproxy[6] = {2, 0, 2, 3, 0, 0};
__u8 special_mac_from_tproxy[6] = {2, 0, 2, 3, 0, 1};

// Routing and redirect the packet back.
// We cannot modify the dest address here. So we cooperate with wan_ingress.
SEC("tc/wan_egress")
int tproxy_wan_egress(struct __sk_buff *skb) {
  // Skip packets not from localhost.
  if (skb->ingress_ifindex != NOWHERE_IFINDEX) {
    return TC_ACT_OK;
  }
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
  __u32 eth_h_len;
  if (get_eth_h_len(skb->ifindex, &eth_h_len)) {
    return TC_ACT_OK;
  }
  bool tcp_state_syn;
  int ret = parse_transport(skb, eth_h_len, &ethh, &iph, &ipv6h, &icmp6h, &tcph,
                            &udph, &ihl, &l4proto);
  if (ret) {
    return TC_ACT_OK;
  }
  if (l4proto == IPPROTO_ICMPV6) {
    return TC_ACT_OK;
  }

  // Backup for further use.
  struct tuples tuples;
  get_tuples(skb, &tuples, &iph, &ipv6h, &tcph, &udph, l4proto);

  // We should know if this packet is from tproxy.
  // We do not need to check the source ip because we have skipped packets not
  // from localhost.
  __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
  if (!tproxy_port) {
    return TC_ACT_OK;
  }
  bool tproxy_response = *tproxy_port == tuples.sport;
  // Double check to avoid conflicts when binding wan and lan to the same
  // interface.
  if (tproxy_response && l4proto == IPPROTO_TCP) {
    // If it is a TCP first handshake, it is not a tproxy response.
    if (tcph.syn && !tcph.ack) {
      tproxy_response = false;
      // Abnormal.
      return TC_ACT_SHOT;
    } else {
      // If there is an existing socket on localhost, it is not a tproxy
      // response.
      struct bpf_sock_tuple tuple = {0};
      __u32 tuple_size;
      if (skb->protocol == bpf_htons(ETH_P_IP)) {
        tuple.ipv4.daddr = tuples.dip.u6_addr32[3];
        tuple.ipv4.saddr = tuples.sip.u6_addr32[3];
        tuple.ipv4.dport = tuples.dport;
        tuple.ipv4.sport = tuples.sport;
        tuple_size = sizeof(tuple.ipv4);
      } else {
        __builtin_memcpy(tuple.ipv6.daddr, &tuples.dip, IPV6_BYTE_LENGTH);
        __builtin_memcpy(tuple.ipv6.saddr, &tuples.sip, IPV6_BYTE_LENGTH);
        tuple.ipv6.dport = tuples.dport;
        tuple.ipv6.sport = tuples.sport;
        tuple_size = sizeof(tuple.ipv6);
      }
      struct bpf_sock *sk =
          bpf_skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);
      if (sk) {
        // Not a tproxy WAN response. It is a tproxy LAN response.
        bpf_sk_release(sk);
        return TC_ACT_PIPE;
      }
    }
  }

  if (tproxy_response) {
    // Packets from tproxy port.
    // We need to redirect it to original port.

    // bpf_printk("tproxy_response: %pI6:%u", tuples.dip.u6_addr32,
    // bpf_ntohs(tuples.dport));

    // Write mac.
    if ((ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
                                   ethh.h_source, sizeof(ethh.h_source), 0))) {
      return TC_ACT_SHOT;
    }
    if ((ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
                                   special_mac_from_tproxy,
                                   sizeof(ethh.h_source), 0))) {
      return TC_ACT_SHOT;
    };
  } else {
    // Normal packets.

    if (l4proto == IPPROTO_TCP) {
      // Backup for further use.
      tcp_state_syn = tcph.syn && !tcph.ack;
      struct ip_port key_src;
      __builtin_memset(&key_src, 0, sizeof(key_src));
      // Use daddr as key in WAN because tproxy (control plane) also lookups the
      // map element using income client ip (that is daddr).
      __builtin_memcpy(&key_src.ip, &tuples.dip, IPV6_BYTE_LENGTH);
      key_src.port = tcph.source;
      __u8 outbound;
      bool must;
      __u32 mark;
      struct pid_pname *pid_pname = NULL;
      if (unlikely(tcp_state_syn)) {
        // New TCP connection.
        // bpf_printk("[%X]New Connection", bpf_ntohl(tcph.seq));
        __u32 flag[6] = {L4ProtoType_TCP}; // TCP
        if (skb->protocol == bpf_htons(ETH_P_IP)) {
          flag[1] = IpVersionType_4;
        } else {
          flag[1] = IpVersionType_6;
        }
        if (pid_is_control_plane(skb, &pid_pname)) {
          // From control plane. Direct.
          return TC_ACT_OK;
        }
        if (pid_pname) {
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
        if ((s64_ret = route(flag, &tcph, tuples.sip.u6_addr32,
                             tuples.dip.u6_addr32, mac)) < 0) {
          bpf_printk("shot routing: %d", s64_ret);
          return TC_ACT_SHOT;
        }

        outbound = s64_ret;
        mark = s64_ret >> 8;
        must = (s64_ret >> 40) & 1;

#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
        // Print only new connection.
        __u32 pid = pid_pname ? pid_pname->pid : 0;
        bpf_printk("tcp(wan): from %pI6:%u [PID %u]", tuples.sip.u6_addr32,
                   bpf_ntohs(tuples.sport), pid);
        bpf_printk("tcp(wan): outbound: %u, %pI6:%u", outbound,
                   tuples.dip.u6_addr32, bpf_ntohs(tuples.dport));
#endif
      } else {
        // bpf_printk("[%X]Old Connection", bpf_ntohl(tcph.seq));
        // The TCP connection exists.
        struct dst_routing_result *dst =
            bpf_map_lookup_elem(&tcp_dst_map, &key_src);
        if (!dst) {
          // Do not impact previous connections and server connections.
          return TC_ACT_OK;
        }
        outbound = dst->routing_result.outbound;
        mark = dst->routing_result.mark;
        must = dst->routing_result.must;
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
          !(l4proto == IPPROTO_UDP && tuples.dport == bpf_htons(53))) {
        // Outbound is not alive. Dns is an exception.
        return TC_ACT_SHOT;
      }

      if (unlikely(tcp_state_syn)) {
        struct dst_routing_result routing_info;
        __builtin_memset(&routing_info, 0, sizeof(routing_info));
        __builtin_memcpy(routing_info.ip, &tuples.dip, IPV6_BYTE_LENGTH);
        routing_info.port = tcph.dest;
        routing_info.routing_result.outbound = outbound;
        routing_info.routing_result.mark = mark;
        routing_info.routing_result.must = must;
        __builtin_memcpy(routing_info.routing_result.mac, ethh.h_source,
                         sizeof(ethh.h_source));
        if (pid_pname) {
          __builtin_memcpy(routing_info.routing_result.pname, pid_pname->pname,
                           TASK_COMM_LEN);
          routing_info.routing_result.pid = pid_pname->pid;
        }
        // bpf_printk("UPDATE: %pI6:%u", key_src.ip.u6_addr32,
        // bpf_ntohs(key_src.port));
        bpf_map_update_elem(&tcp_dst_map, &key_src, &routing_info, BPF_ANY);
      }

      // Write mac.
      if ((ret =
               bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
                                   ethh.h_source, sizeof(ethh.h_source), 0))) {
        return TC_ACT_SHOT;
      }
      if ((ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
                                     special_mac_to_tproxy,
                                     sizeof(ethh.h_source), 0))) {
        return TC_ACT_SHOT;
      };

    } else if (l4proto == IPPROTO_UDP) {

      // Routing. It decides if we redirect traffic to control plane.
      __u32 flag[6] = {L4ProtoType_UDP};
      if (skb->protocol == bpf_htons(ETH_P_IP)) {
        flag[1] = IpVersionType_4;
      } else {
        flag[1] = IpVersionType_6;
      }
      struct pid_pname *pid_pname;
      if (pid_is_control_plane(skb, &pid_pname)) {
        // From control plane. Direct.
        return TC_ACT_OK;
      }
      if (pid_pname) {
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
      if ((s64_ret = route(flag, &udph, tuples.sip.u6_addr32,
                           tuples.dip.u6_addr32, mac)) < 0) {
        bpf_printk("shot routing: %d", s64_ret);
        return TC_ACT_SHOT;
      }
      // Construct new hdr to encap.
      struct dst_routing_result new_hdr;
      __builtin_memset(&new_hdr, 0, sizeof(new_hdr));
      __builtin_memcpy(new_hdr.ip, &tuples.dip, IPV6_BYTE_LENGTH);
      new_hdr.port = udph.dest;
      new_hdr.recognize = RECOGNIZE;
      new_hdr.routing_result.outbound = s64_ret;
      new_hdr.routing_result.mark = s64_ret >> 8;
      new_hdr.routing_result.must = (s64_ret >> 40) & 1;
      __builtin_memcpy(new_hdr.routing_result.mac, ethh.h_source,
                       sizeof(ethh.h_source));
      if (pid_pname) {
        __builtin_memcpy(new_hdr.routing_result.pname, pid_pname->pname,
                         TASK_COMM_LEN);
        new_hdr.routing_result.pid = pid_pname->pid;
      }
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
      __u32 pid = pid_pname ? pid_pname->pid : 0;
      bpf_printk("udp(wan): from %pI6:%u [PID %u]", tuples.sip.u6_addr32,
                 bpf_ntohs(tuples.sport), pid);
      bpf_printk("udp(wan): outbound: %u, %pI6:%u",
                 new_hdr.routing_result.outbound, tuples.dip.u6_addr32,
                 bpf_ntohs(tuples.dport));
#endif

      if (new_hdr.routing_result.outbound == OUTBOUND_DIRECT &&
          new_hdr.routing_result.mark ==
              0 // If mark is not zero, we should re-route it, so we
                // send it to control plane in WAN.
      ) {
        return TC_ACT_OK;
      } else if (unlikely(new_hdr.routing_result.outbound == OUTBOUND_BLOCK)) {
        return TC_ACT_SHOT;
      }

      // Rewrite to control plane.

      // Check outbound connectivity in specific ipversion and l4proto.
      struct outbound_connectivity_query q = {0};
      q.outbound = new_hdr.routing_result.outbound;
      q.ipversion = skb->protocol == bpf_htons(ETH_P_IP) ? 4 : 6;
      q.l4proto = l4proto;
      __u32 *alive;
      alive = bpf_map_lookup_elem(&outbound_connectivity_map, &q);
      if (alive && *alive == 0 &&
          !(l4proto == IPPROTO_UDP && tuples.dport == bpf_htons(53))) {
        // Outbound is not alive. Dns is an exception.
        return TC_ACT_SHOT;
      }

      // Write mac.
      if ((ret =
               bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
                                   ethh.h_source, sizeof(ethh.h_source), 0))) {
        return TC_ACT_SHOT;
      }
      if ((ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
                                     special_mac_to_tproxy,
                                     sizeof(ethh.h_source), 0))) {
        return TC_ACT_SHOT;
      };

      // Encap a header to transmit fullcone tuple.
      __u32 t_eth_h_len;
      if (get_eth_h_len(skb->ifindex, &t_eth_h_len)) {
        return TC_ACT_OK;
      }
      if ((ret = encap_after_udp_hdr(
               skb, t_eth_h_len, ihl,
               skb->protocol == bpf_htons(ETH_P_IP) ? iph.tot_len : 0, &new_hdr,
               sizeof(new_hdr), true))) {
        return TC_ACT_SHOT;
      }
    }
  }

  // // Print packet in hex for debugging (checksum or something else).
  // if ((l4proto == IPPROTO_TCP ? tcph.dest : udph.dest) == bpf_htons(8443)) {
  //   bpf_printk("PRINT OUTPUT PACKET");
  //   for (__u32 i = 0; i < skb->len && i < 500; i++) {
  //     __u8 t = 0;
  //     bpf_skb_load_bytes(skb, i, &t, 1);
  //     bpf_printk("%02x", t);
  //   }
  // }
  __u32 t_eth_h_len;
  if (get_eth_h_len(skb->ifindex, &t_eth_h_len)) {
    return TC_ACT_OK;
  }
  disable_l4_checksum(skb, t_eth_h_len, l4proto, ihl);

  // Redirect from egress to ingress.
  if ((ret = bpf_redirect(skb->ifindex, BPF_F_INGRESS)) == TC_ACT_SHOT) {
    bpf_printk("Shot bpf_redirect: %d", ret);
    return TC_ACT_SHOT;
  }
  return TC_ACT_REDIRECT;
}

SEC("tc/wan_ingress")
int tproxy_wan_ingress(struct __sk_buff *skb) {
  struct ethhdr ethh;
  struct iphdr iph;
  struct ipv6hdr ipv6h;
  struct icmp6hdr icmp6h;
  struct tcphdr tcph;
  struct udphdr udph;
  __u8 ihl;
  __u8 l4proto;
  __u32 eth_h_len;
  if (get_eth_h_len(skb->ifindex, &eth_h_len)) {
    return TC_ACT_OK;
  }
  int ret = parse_transport(skb, eth_h_len, &ethh, &iph, &ipv6h, &icmp6h, &tcph,
                            &udph, &ihl, &l4proto);
  if (ret) {
    return TC_ACT_OK;
  }
  if (l4proto == IPPROTO_ICMPV6) {
    return TC_ACT_OK;
  }

  struct tuples tuples;
  get_tuples(skb, &tuples, &iph, &ipv6h, &tcph, &udph, l4proto);
  // bpf_printk("bpf_ntohs(*(__u16 *)&ethh.h_source[4]): %u",
  //            bpf_ntohs(*(__u16 *)&ethh.h_source[4]));
  // Tproxy related.
  __u16 tproxy_typ = bpf_ntohs(*(__u16 *)&ethh.h_source[4]);
  if (*(__u32 *)&ethh.h_source[0] != bpf_htonl(0x02000203) || tproxy_typ > 1) {
    // Check for security. Reject packets that is UDP and sent to tproxy port.
    __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
    if (!tproxy_port) {
      goto accept;
    }
    if (unlikely(*tproxy_port == tuples.dport)) {
      struct bpf_sock_tuple tuple = {0};
      __u32 tuple_size;

      if (skb->protocol == bpf_htons(ETH_P_IP)) {
        tuple.ipv4.daddr = tuples.dip.u6_addr32[3];
        tuple.ipv4.dport = tuples.dport;
        tuple_size = sizeof(tuple.ipv4);
      } else {
        __builtin_memcpy(tuple.ipv6.daddr, &tuples.dip, IPV6_BYTE_LENGTH);
        tuple.ipv6.dport = tuples.dport;
        tuple_size = sizeof(tuple.ipv6);
      }

      struct bpf_sock *sk =
          bpf_sk_lookup_udp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);
      if (sk) {
        // Scope is host.
        bpf_sk_release(sk);
        return TC_ACT_SHOT;
      }
    }
  accept:
    return TC_ACT_PIPE;
  }
  bool tproxy_response = tproxy_typ == 1;

  // // Print packet in hex for debugging (checksum or something else).
  // if (dport == bpf_htons(8443)) {
  //   bpf_printk("PRINT BEFORE PACKET");
  //   for (__u32 i = 0; i < skb->len && i < 500; i++) {
  //     __u8 t = 0;
  //     bpf_skb_load_bytes(skb, i, &t, 1);
  //     bpf_printk("%02x", t);
  //   }
  // }
  if (tproxy_response) {
    // Send the tproxy response packet to origin.

    // If a client sent a packet at the begining, let's say the client is
    // sender and its ip is right host ip.
    // saddr is host ip and right sender ip.
    // Now when tproxy responses, dport is sender's sport. See (1) below. daddr
    // is original dest ip (target address).

    // bpf_printk("[%u]should send to origin: %pI6:%u",
    // l4proto, saddr,
    //            bpf_ntohs(dport));

    if (l4proto == IPPROTO_TCP) {
      // Lookup original dest as sip and sport.
      struct ip_port key_dst;
      __builtin_memset(&key_dst, 0, sizeof(key_dst));
      // Use daddr as key in WAN because tproxy (control plane) also lookups the
      // map element using income client ip (that is daddr).
      __builtin_memcpy(&key_dst.ip, &tuples.dip, IPV6_BYTE_LENGTH);
      key_dst.port = tcph.dest;
      struct dst_routing_result *original_dst =
          bpf_map_lookup_elem(&tcp_dst_map, &key_dst);
      if (!original_dst) {
        bpf_printk("[%X]Bad Connection: to: %pI6:%u", bpf_ntohl(tcph.seq),
                   key_dst.ip.u6_addr32, bpf_ntohs(key_dst.port));
        return TC_ACT_SHOT;
      }

      // Rewrite sip and sport.
      if ((ret = rewrite_ip(skb, eth_h_len, IPPROTO_TCP, ihl,
                            tuples.sip.u6_addr32, original_dst->ip, false,
                            true))) {
        bpf_printk("Shot IP: %d", ret);
        return TC_ACT_SHOT;
      }
      if ((ret = rewrite_port(skb, eth_h_len, IPPROTO_TCP, ihl, tuples.sport,
                              original_dst->port, false, true))) {
        bpf_printk("Shot Port: %d", ret);
        return TC_ACT_SHOT;
      }
    } else if (l4proto == IPPROTO_UDP) {

      /// NOTICE: Actually, we do not need symmetrical headers in client and
      /// server. We use it for convinience. This behavior may change in the
      /// future. Outbound here is useless and redundant.
      struct dst_routing_result ori_src;

      // Get source ip/port from our packet header.

      // Decap header to get fullcone tuple.
      if ((ret = decap_after_udp_hdr(
               skb, eth_h_len, ihl,
               skb->protocol == bpf_htons(ETH_P_IP) ? iph.tot_len : 0, &ori_src,
               sizeof(ori_src), NULL, true))) {
        return TC_ACT_SHOT;
      }

      // Rewrite udp src ip
      if ((ret = rewrite_ip(skb, eth_h_len, IPPROTO_UDP, ihl,
                            tuples.sip.u6_addr32, ori_src.ip, false, true))) {
        bpf_printk("Shot IP: %d", ret);
        return TC_ACT_SHOT;
      }

      // Rewrite udp src port
      if ((ret = rewrite_port(skb, eth_h_len, IPPROTO_UDP, ihl, tuples.sport,
                              ori_src.port, false, true))) {
        bpf_printk("Shot Port: %d", ret);
        return TC_ACT_SHOT;
      }

      // bpf_printk("real from: %pI6:%u", ori_src.ip, bpf_ntohs(ori_src.port));

      // Print packet in hex for debugging (checksum or something else).
      // bpf_printk("UDP EGRESS OK");
      // for (__u32 i = 0; i < skb->len && i < 1500; i++) {
      //   __u8 t = 0;
      //   bpf_skb_load_bytes(skb, i, &t, 1);
      //   bpf_printk("%02x", t);
      // }
    }
    // Rewrite dip to host ip.
    if ((ret = rewrite_ip(skb, eth_h_len, l4proto, ihl, tuples.dip.u6_addr32,
                          tuples.sip.u6_addr32, true, true))) {
      bpf_printk("Shot IP: %d", ret);
      return TC_ACT_SHOT;
    }
  } else {
    // Should send the packet to tproxy.

    // Get tproxy ip and port.
    // saddr should be tproxy ip.
    __be32 *tproxy_ip = tuples.sip.u6_addr32;
    // __builtin_memcpy(tproxy_ip, saddr, sizeof(tproxy_ip));
    __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
    if (!tproxy_port) {
      return TC_ACT_OK;
    }
    // bpf_printk("should send to: %pI6:%u", tproxy_ip,
    // bpf_ntohs(*tproxy_port));

    if ((ret = rewrite_ip(skb, eth_h_len, l4proto, ihl, tuples.dip.u6_addr32,
                          tproxy_ip, true, true))) {
      bpf_printk("Shot IP: %d", ret);
      return TC_ACT_SHOT;
    }

    // Rewrite dst port.
    if ((ret = rewrite_port(skb, eth_h_len, l4proto, ihl, tuples.dport,
                            *tproxy_port, true, true))) {
      bpf_printk("Shot Port: %d", ret);
      return TC_ACT_SHOT;
    }

    // (1) Use daddr as saddr to pass NIC verification. Notice that we do not
    // modify the <sport> so tproxy will send packet to it.
    if ((ret = rewrite_ip(skb, eth_h_len, l4proto, ihl, tuples.sip.u6_addr32,
                          tuples.dip.u6_addr32, false, true))) {
      bpf_printk("Shot IP: %d", ret);
      return TC_ACT_SHOT;
    }
  }

  // // Print packet in hex for debugging (checksum or something else).
  // if (dport == bpf_htons(8443)) {
  //   bpf_printk("PRINT AFTER PACKET");
  //   for (__u32 i = 0; i < skb->len && i < 500; i++) {
  //     __u8 t = 0;
  //     bpf_skb_load_bytes(skb, i, &t, 1);
  //     bpf_printk("%02x", t);
  //   }
  // }

  return TC_ACT_OK;
}

static int __always_inline _update_map_elem_by_cookie(const __u64 cookie) {
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

  /**
  For string like: /usr/lib/sddm/sddm-helper --socket /tmp/sddm-auth1
  We extract "sddm-helper" from it.
  */
  unsigned long loc, j, last_slash = -1;
#pragma unroll
  for (loc = 0, j = 0; j < MAX_ARG_LEN_TO_PROBE;
       ++j, loc = ((loc + 1) & (MAX_ARG_SCANNER_BUFFER_SIZE - 1))) {
    // volatile unsigned long k = j; // Cheat to unroll.
    if (unlikely(arg_start + j >= arg_end)) {
      break;
    }
    if (unlikely(loc == 0)) {
      /// WANRING: Do NOT use bpf_core_read_user_str, it will bring terminator
      /// 0.
      // __builtin_memset(&buf, 0, MAX_ARG_SCANNER_BUFFER_SIZE);
      unsigned long to_read = arg_end - (arg_start + j);
      if (to_read >= MAX_ARG_SCANNER_BUFFER_SIZE) {
        to_read = MAX_ARG_SCANNER_BUFFER_SIZE;
      } else {
        buf[to_read] = 0;
      }
      if ((ret = bpf_core_read_user(&buf, to_read,
                                    (const void *)(arg_start + j)))) {
        // bpf_printk("failed to read process name.0: [%ld, %ld]", arg_start,
        //            arg_end);
        // bpf_printk("_failed to read process name.0: %ld %ld", j, to_read);
        return ret;
      }
    }
    if (unlikely(buf[loc] == '/')) {
      last_slash = j;
    } else if (unlikely(buf[loc] == ' ' || buf[loc] == 0)) {
      break;
    }
  }
  ++last_slash;
  unsigned long length_cpy = j - last_slash;
  if (length_cpy > TASK_COMM_LEN) {
    length_cpy = TASK_COMM_LEN;
  }
  if ((ret = bpf_core_read_user(&val.pname, length_cpy,
                                (const void *)(arg_start + last_slash)))) {
    bpf_printk("failed to read process name.1: %d", ret);
    return ret;
  }
  if ((ret = bpf_core_read(&val.pid, sizeof(val.pid), &current->tgid))) {
    bpf_printk("failed to read pid: %d", ret);
    return ret;
  }
  // bpf_printk("a start_end: %lu %lu", arg_start, arg_end);
  // bpf_printk("b start_end: %lu %lu", arg_start + last_slash, arg_start + j);

  // Update map.
  if (unlikely(
          ret = bpf_map_update_elem(&cookie_pid_map, &cookie, &val, BPF_ANY))) {
    // bpf_printk("setup_mapping_from_sk: failed update map: %d", ret);
    return ret;
  }
  bpf_map_update_elem(&tgid_pname_map, &val.pid, &val.pname, BPF_ANY);

#ifdef __PRINT_SETUP_PROCESS_CONNNECTION
  bpf_printk("setup_mapping: %llu -> %s (%d)", cookie, val.pname, val.pid);
#endif
  return 0;
}

static int __always_inline update_map_elem_by_cookie(const __u64 cookie) {
  int ret;

  if ((ret = _update_map_elem_by_cookie(cookie))) {
    // Fallback to only write pid to avoid loop due to packets sent by dae.
    struct pid_pname val = {0};
    val.pid = bpf_get_current_pid_tgid() >> 32;
    __u32(*pname)[TASK_COMM_LEN] =
        bpf_map_lookup_elem(&tgid_pname_map, &val.pid);
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
int tproxy_wan_cg_sock_create(struct bpf_sock *sk) {
  update_map_elem_by_cookie(bpf_get_socket_cookie(sk));
  return 1;
}
// Remove cookie to pid, pname mapping.
SEC("cgroup/sock_release")
int tproxy_wan_cg_sock_release(struct bpf_sock *sk) {
  __u64 cookie = bpf_get_socket_cookie(sk);
  if (unlikely(!cookie)) {
    bpf_printk("zero cookie");
    return 1;
  }
  bpf_map_delete_elem(&cookie_pid_map, &cookie);
  return 1;
}
SEC("cgroup/connect4")
int tproxy_wan_cg_connect4(struct bpf_sock_addr *ctx) {
  update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
  return 1;
}
SEC("cgroup/connect6")
int tproxy_wan_cg_connect6(struct bpf_sock_addr *ctx) {
  update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
  return 1;
}
SEC("cgroup/sendmsg4")
int tproxy_wan_cg_sendmsg4(struct bpf_sock_addr *ctx) {
  update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
  return 1;
}
SEC("cgroup/sendmsg6")
int tproxy_wan_cg_sendmsg6(struct bpf_sock_addr *ctx) {
  update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
  return 1;
}

SEC("license") const char __license[] = "Dual BSD/GPL";
