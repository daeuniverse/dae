// +build ignore
/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */

#include <asm-generic/errno-base.h>

#include "headers/if_ether_defs.h"
#include "headers/pkt_cls_defs.h"
#include "headers/socket_defs.h"
#include "headers/vmlinux.h"

// #include <bpf/bpf_core_read.h>
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_probe_read.h"

// #define __DEBUG_ROUTING
// #define __PRINT_ROUTING_RESULT
// #define __REMOVE_BPF_PRINTK

#ifdef __REMOVE_BPF_PRINTK
#undef bpf_printk
#define bpf_printk(...) (void)0
#endif

// #define likely(x) x
// #define unlikely(x) x
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

#define IPV6_BYTE_LENGTH 16
#define TASK_COMM_LEN 16

#define IPV4_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IPV4_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IPV4_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IPV6_DST_OFF (ETH_HLEN + offsetof(struct ipv6hdr, daddr))
#define IPV6_SRC_OFF (ETH_HLEN + offsetof(struct ipv6hdr, saddr))

#define NOWHERE_IFINDEX 0
#define LOOPBACK_IFINDEX 1
#define LOOPBACK_ADDR 0x7f000001

#define MAX_PARAM_LEN 16
#define MAX_INTERFACE_NUM 128
#define MAX_MATCH_SET_LEN (32 * 3)
#define MAX_LPM_SIZE 20480
//#define MAX_LPM_SIZE 20480
#define MAX_LPM_NUM (MAX_MATCH_SET_LEN + 8)
#define MAX_DST_MAPPING_NUM (65536 * 2)
#define MAX_SRC_PID_PNAME_MAPPING_NUM (65536)
#define IPV6_MAX_EXTENSIONS 4
#define MAX_ARG_LEN_TO_PROBE 192
#define MAX_ARG_SCANNER_BUFFER_SIZE (TASK_COMM_LEN * 4)

#define OUTBOUND_DIRECT 0
#define OUTBOUND_BLOCK 1
#define OUTBOUND_CONTROL_PLANE_DIRECT 0xFD
#define OUTBOUND_LOGICAL_OR 0xFE
#define OUTBOUND_LOGICAL_AND 0xFF
#define OUTBOUND_LOGICAL_MASK 0xFE

#define TPROXY_MARK 0x80000000

#define ESOCKTNOSUPPORT 94 /* Socket type not supported */

enum { BPF_F_CURRENT_NETNS = -1 };

enum {
  DisableL4ChecksumPolicy_EnableL4Checksum,
  DisableL4ChecksumPolicy_Restore,
  DisableL4ChecksumPolicy_SetZero,
};

// Sockmap:
struct {
  __uint(type, BPF_MAP_TYPE_SOCKMAP);
  __type(key, __u32);   // 0 is tcp, 1 is udp.
  __type(value, __u64); // fd of socket.
  __uint(max_entries, 2);
} listen_socket_map SEC(".maps");

// Param keys:
static const __u32 zero_key = 0;
static const __u32 tproxy_port_key = 1;
static const __u32 one_key = 1;
static const __u32 disable_l4_tx_checksum_key
    __attribute__((unused, deprecated)) = 2;
static const __u32 disable_l4_rx_checksum_key
    __attribute__((unused, deprecated)) = 3;
static const __u32 control_plane_pid_key = 4;

struct ip_port {
  __be32 ip[4];
  __be16 port;
};

struct ip_port_outbound {
  __be32 ip[4];
  __be16 port;
  __u8 outbound;
  __u8 unused;
};

struct tuples {
  struct ip_port src;
  struct ip_port dst;
  __u8 l4proto;
};

/// TODO: Remove items from the dst_map by conntrack.
// Dest map:
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key,
         struct ip_port); // As TCP client side [SYN, !ACK],
                          // (source ip, source port, tcp) is
                          // enough for identifier. And UDP client
                          // side does not care it (full-cone).
  __type(value, struct ip_port_outbound); // Original target.
  __uint(max_entries, MAX_DST_MAPPING_NUM);
  /// NOTICE: It MUST be pinned.
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_dst_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct tuples);
  __type(value, __u32); // outbound
  __uint(max_entries, MAX_DST_MAPPING_NUM);
} routing_tuples_map SEC(".maps");

// Params:
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_PARAM_LEN);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} param_map SEC(".maps");

// LPM key:
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, __u32);
  __type(value, struct lpm_key);
  __uint(max_entries, 3);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} lpm_key_map SEC(".maps");

// h_sport, h_dport:
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, __u32);
  __type(value, __u16);
  __uint(max_entries, 2);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} h_port_map SEC(".maps");

// l4proto, ipversion:
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 2);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} l4proto_ipversion_map SEC(".maps");

// IPPROTO to hdr_size
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __s32);
  __uint(max_entries, 5);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} ipproto_hdrsize_map SEC(".maps");

// Dns upstream:
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct ip_port);
  __uint(max_entries, 1);
} dns_upstream_map SEC(".maps");

// Interface Ips:
struct if_params {
  __be32 ip4[4];
  __be32 ip6[4];

  bool has_ip4;
  bool has_ip6;
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
} unused_lpm_type SEC(".maps"), host_ip_lpm SEC(".maps");
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
  MatchType_Final,
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
  __uint(max_entries, 65535);
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
  __uint(max_entries, MAX_SRC_PID_PNAME_MAPPING_NUM);
  /// NOTICE: No persistence.
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} cookie_pid_map SEC(".maps");

// Functions:

static __always_inline bool equal16(const __be32 x[4], const __be32 y[4]) {
#if __clang_major__ >= 10
  return ((__be64 *)x)[0] == ((__be64 *)y)[0] &&
         ((__be64 *)x)[1] == ((__be64 *)y)[1];
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

static __always_inline __u32 l4_checksum_off(__u8 proto, __u8 ihl) {
  return ETH_HLEN + ihl * 4 + l4_checksum_rel_off(proto);
}

static __always_inline int bpf_update_offload_l4cksm_32(struct __sk_buff *skb,
                                                        __u32 l4_cksm_off,
                                                        __be32 old,
                                                        __be32 new) {
  int ret;
  __sum16 cksm;
  if ((ret = bpf_skb_load_bytes(skb, l4_cksm_off, &cksm, sizeof(cksm)))) {
    return ret;
  }
  //  bpf_printk("before: %x", bpf_ntohs(cksm));
  cksm =
      bpf_htons(bpf_ntohs(cksm) + bpf_ntohs(*(__be16 *)&new) +
                bpf_ntohs(*((__be16 *)&new + 1)) - bpf_ntohs(*(__be16 *)&old) -
                bpf_ntohs(*((__be16 *)&old + 1)));
  if ((ret = bpf_skb_store_bytes(skb, l4_cksm_off, &cksm, sizeof(cksm), 0))) {
    return ret;
  }
  //  bpf_printk("after: %x", bpf_ntohs(cksm));
  return 0;
}

static __always_inline int bpf_update_offload_l4cksm_16(struct __sk_buff *skb,
                                                        __u32 l4_cksm_off,
                                                        __be16 old,
                                                        __be16 new) {
  int ret;
  __sum16 cksm;
  if ((ret = bpf_skb_load_bytes(skb, l4_cksm_off, &cksm, sizeof(cksm)))) {
    return ret;
  }
  //  bpf_printk("before: %x", bpf_ntohs(cksm));
  cksm = bpf_htons(bpf_ntohs(cksm) + bpf_ntohs(new) - bpf_ntohs(old));
  if ((ret = bpf_skb_store_bytes(skb, l4_cksm_off, &cksm, sizeof(cksm), 0))) {
    return ret;
  }
  //  bpf_printk("after: %x", bpf_ntohs(cksm));
  return 0;
}

static __always_inline int rewrite_ip(struct __sk_buff *skb, __u8 ipversion,
                                      __u8 proto, __u8 ihl, __be32 old_ip[4],
                                      __be32 new_ip[4], bool is_dest,
                                      bool calc_l4_cksm) {
  // Nothing to do.
  if (equal16(old_ip, new_ip)) {
    return 0;
  }
  // bpf_printk("%pI6->%pI6", old_ip, new_ip);

  __u32 l4_cksm_off = l4_checksum_off(proto, ihl);
  int ret;
  // BPF_F_PSEUDO_HDR indicates the part we want to modify is part of the
  // pseudo header.
  __u32 l4flags = BPF_F_PSEUDO_HDR;
  if (proto == IPPROTO_UDP) {
    l4flags |= BPF_F_MARK_MANGLED_0;
  }

  if (ipversion == 4) {

    __be32 _old_ip = old_ip[3];
    __be32 _new_ip = new_ip[3];
    if (calc_l4_cksm) {

      int ret;
      // __sum16 test;
      // bpf_skb_load_bytes(skb, l4_cksm_off, &test, sizeof(test));
      // bpf_printk("rewrite ip before: %x, %pI4->%pI4", test, &_old_ip,
      // &_new_ip);
      if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, _old_ip, _new_ip,
                                     l4flags | sizeof(_new_ip)))) {
        bpf_printk("bpf_l4_csum_replace: %d", ret);
        return ret;
      }
    } else {
      // NIC checksum offload path. But problem remains. FIXME.
      if ((ret = bpf_update_offload_l4cksm_32(skb, l4_cksm_off, _old_ip,
                                              _new_ip))) {
        bpf_printk("bpf_update_offload_cksm_32: %d", ret);
        return ret;
      }
    }
    // bpf_skb_load_bytes(skb, l4_cksm_off, &test, sizeof(test));
    // bpf_printk("rewrite ip after: %x", test);

    if ((ret = bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, _old_ip, _new_ip,
                                   sizeof(_new_ip)))) {
      return ret;
    }
    // bpf_printk("%pI4 -> %pI4", &_old_ip, &_new_ip);

    ret = bpf_skb_store_bytes(skb, is_dest ? IPV4_DST_OFF : IPV4_SRC_OFF,
                              &_new_ip, sizeof(_new_ip), 0);
    if (ret) {
      bpf_printk("bpf_skb_store_bytes: %d", ret);
      return ret;
    }
  } else {

    if (calc_l4_cksm) {
      __s64 cksm =
          bpf_csum_diff(old_ip, IPV6_BYTE_LENGTH, new_ip, IPV6_BYTE_LENGTH, 0);
      if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, 0, cksm, l4flags))) {
        bpf_printk("bpf_l4_csum_replace: %d", ret);
        return ret;
      }
    }
    // bpf_printk("%pI6 -> %pI6", old_ip, new_ip);

    ret = bpf_skb_store_bytes(skb, is_dest ? IPV6_DST_OFF : IPV6_SRC_OFF,
                              new_ip, IPV6_BYTE_LENGTH, 0);
    if (ret) {
      bpf_printk("bpf_skb_store_bytes: %d", ret);
      return ret;
    }
  }

  return 0;
}

static __always_inline int rewrite_port(struct __sk_buff *skb, __u8 proto,
                                        __u8 ihl, __be16 old_port,
                                        __be16 new_port, bool is_dest,
                                        bool calc_l4_cksm) {
  // Nothing to do.
  if (old_port == new_port) {
    return 0;
  }
  __u32 cksm_off = l4_checksum_off(proto, ihl), port_off = ETH_HLEN + ihl * 4;
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
  // __sum16 test;
  // if (!bpf_skb_load_bytes(skb, cksm_off, &test, sizeof(test))) {
  //   bpf_printk("rewrite port before: %x, %u->%u", test, bpf_ntohs(old_port),
  //              bpf_ntohs(new_port));
  // }
  if (calc_l4_cksm) {
    if ((ret = bpf_l4_csum_replace(skb, cksm_off, old_port, new_port,
                                   l4flags | sizeof(new_port)))) {
      bpf_printk("bpf_l4_csum_replace: %d", ret);
      return ret;
    }
  }
  // if (!bpf_skb_load_bytes(skb, cksm_off, &test, sizeof(test))) {
  //   bpf_printk("rewrite port aftetr: %x", test);
  // }

  if ((ret = bpf_skb_store_bytes(skb, port_off, &new_port, sizeof(new_port),
                                 0))) {
    return ret;
  }
  return 0;
}

static __always_inline int handle_ipv6_extensions(const struct __sk_buff *skb,
                                                  __u32 offset, __u32 hdr,
                                                  struct tcphdr *tcph,
                                                  struct udphdr *udph,
                                                  __u8 *ihl, __u8 *l4proto) {
  __u8 hdr_length = 0;
  __s32 *p_s32;
  __u8 nexthdr = 0;
  *ihl = sizeof(struct ipv6hdr) / 4;
  int ret;
  // We only process TCP and UDP traffic.

#pragma unroll
  for (int i = 0; i < IPV6_MAX_EXTENSIONS;
       i++, offset += hdr_length, hdr = nexthdr, *ihl += hdr_length / 4) {
    if (hdr_length % 4) {
      bpf_printk("IPv6 extension length is not multiples of 4");
      return 1;
    }
    // See component/control/control_plane.go.
    if (!(p_s32 = bpf_map_lookup_elem(&ipproto_hdrsize_map, &hdr))) {
      return 1;
    }

    switch (*p_s32) {
    case -1:
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
    case 4:
      hdr_length = 4;
      goto special_n1;
    case -2:
      *l4proto = hdr;
      if (hdr == IPPROTO_TCP) {
        __builtin_memset(tcph, 0, sizeof(struct udphdr));
        // Upper layer;
        if ((ret = bpf_skb_load_bytes(skb, offset, tcph,
                                      sizeof(struct tcphdr)))) {
          bpf_printk("not a valid IPv6 packet");
          return -EFAULT;
        }
      } else if (hdr == IPPROTO_UDP) {
        __builtin_memset(tcph, 0, sizeof(struct tcphdr));
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
      // Unknown hdr.
      return 1;
    }
  }
  bpf_printk("exceeds IPV6_MAX_EXTENSIONS limit");
  return 1;
}

static __always_inline int
parse_transport(const struct __sk_buff *skb, struct ethhdr *ethh,
                struct iphdr *iph, struct ipv6hdr *ipv6h, struct tcphdr *tcph,
                struct udphdr *udph, __u8 *ihl, __u8 *ipversion,
                __u8 *l4proto) {

  __u32 offset = 0;
  int ret;
  ret = bpf_skb_load_bytes(skb, offset, ethh, sizeof(struct ethhdr));
  if (ret) {
    bpf_printk("not ethernet packet");
    return 1;
  }
  // Skip ethhdr for next hdr.
  offset += sizeof(struct ethhdr);

  *ipversion = 0;
  *ihl = 0;
  *l4proto = 0;

  // bpf_printk("parse_transport: h_proto: %u ? %u %u", eth->h_proto,
  //            bpf_htons(ETH_P_IP), bpf_htons(ETH_P_IPV6));
  if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
    __builtin_memset(ipv6h, 0, sizeof(struct ipv6hdr));
    *ipversion = 4;

    if ((ret = bpf_skb_load_bytes(skb, offset, iph, sizeof(struct iphdr)))) {
      return -EFAULT;
    }
    // Skip ipv4hdr and options for next hdr.
    offset += iph->ihl * 4;

    // We only process TCP and UDP traffic.
    *l4proto = iph->protocol;
    if (iph->protocol == IPPROTO_TCP) {
      __builtin_memset(udph, 0, sizeof(struct udphdr));
      if ((ret =
               bpf_skb_load_bytes(skb, offset, tcph, sizeof(struct tcphdr)))) {
        // Not a complete tcphdr.
        return -EFAULT;
      }
    } else if (iph->protocol == IPPROTO_UDP) {
      __builtin_memset(tcph, 0, sizeof(struct tcphdr));
      if ((ret =
               bpf_skb_load_bytes(skb, offset, udph, sizeof(struct udphdr)))) {
        // Not a complete tcphdr.
        return -EFAULT;
      }
    } else {
      // bpf_printk("IP but not TCP/UDP packet: protocol is %u", iph->protocol);
      return 1;
    }
    *ihl = iph->ihl;
    return 0;
  } else if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
    __builtin_memset(iph, 0, sizeof(struct iphdr));
    *ipversion = 6;

    if ((ret =
             bpf_skb_load_bytes(skb, offset, ipv6h, sizeof(struct ipv6hdr)))) {
      bpf_printk("not a valid IPv6 packet");
      return -EFAULT;
    }

    offset += sizeof(struct ipv6hdr);

    return handle_ipv6_extensions(skb, offset, ipv6h->nexthdr, tcph, udph, ihl,
                                  l4proto);
  } else {
    return 1;
  }
}

static __always_inline int adjust_udp_len(struct __sk_buff *skb, __u16 oldlen,
                                          __u32 ihl, __u16 len_diff,
                                          bool calc_l4_cksm) {
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
  __u32 udp_csum_off = l4_checksum_off(IPPROTO_UDP, ihl);
  if (calc_l4_cksm) {
    // replace twice because len exists both pseudo hdr and hdr.
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
  } else {
    // NIC checksum offload path. But problem remains. FIXME.
    if ((ret =
             bpf_update_offload_l4cksm_16(skb, udp_csum_off, oldlen, newlen))) {
      bpf_printk("bpf_update_offload_cksm: %d", ret);
      return ret;
    }
  }
  if ((ret = bpf_skb_store_bytes(
           skb, (__u32)ETH_HLEN + ihl * 4 + offsetof(struct udphdr, len),
           &newlen, sizeof(oldlen), 0))) {
    bpf_printk("bpf_skb_store_bytes newudplen: %d", ret);
    return ret;
  }
  return 0;
}

static __always_inline int adjust_ipv4_len(struct __sk_buff *skb, __u16 oldlen,
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
  if ((ret = bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, oldlen, newlen,
                                 sizeof(oldlen)))) {
    bpf_printk("bpf_l3_csum_replace newudplen: %d", ret);
    return ret;
  }
  if ((ret = bpf_skb_store_bytes(
           skb, (__u32)ETH_HLEN + offsetof(struct iphdr, tot_len), &newlen,
           sizeof(oldlen), 0))) {
    bpf_printk("bpf_skb_store_bytes newiplen: %d", ret);
    return ret;
  }
  return 0;
}

static __always_inline int encap_after_udp_hdr(struct __sk_buff *skb,
                                               __u8 ipversion, __u8 ihl,
                                               __be16 iphdr_tot_len,
                                               void *newhdr, __u32 newhdrlen,
                                               bool calc_l4_cksm) {
  if (unlikely(newhdrlen % 4 != 0)) {
    bpf_printk("encap_after_udp_hdr: unexpected newhdrlen value %u :must "
               "be a multiple of 4",
               newhdrlen);
    return -EINVAL;
  }

  int ret = 0;
  long ip_off = ETH_HLEN;
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
                                 calc_l4_cksm ? BPF_F_ADJ_ROOM_NO_CSUM_RESET
                                              : 0))) {
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
  if (ipversion == 4) {
    if ((ret = adjust_ipv4_len(skb, iphdr_tot_len, newhdrlen))) {
      bpf_printk("adjust_ip_len: %d", ret);
      return ret;
    }
  }

  // Rewrite udp len.
  if ((ret = adjust_udp_len(skb, reserved_udphdr.len, ihl, newhdrlen,
                            calc_l4_cksm))) {
    bpf_printk("adjust_udp_len: %d", ret);
    return ret;
  }

  // Rewrite udp payload.
  if (calc_l4_cksm) {
    __u32 l4_cksm_off = l4_checksum_off(IPPROTO_UDP, ihl);
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

static __always_inline int decap_after_udp_hdr(struct __sk_buff *skb,
                                               __u8 ipversion, __u8 ihl,
                                               __be16 ipv4hdr_tot_len, void *to,
                                               __u32 decap_hdrlen,
                                               bool calc_l4_cksm) {
  if (unlikely(decap_hdrlen % 4 != 0)) {
    bpf_printk("encap_after_udp_hdr: unexpected decap_hdrlen value %u :must "
               "be a multiple of 4",
               decap_hdrlen);
    return -EINVAL;
  }
  int ret = 0;
  long ip_off = ETH_HLEN;
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

  // Adjust room to decap the header.
  if ((ret = bpf_skb_adjust_room(skb, -decap_hdrlen, BPF_ADJ_ROOM_NET,
                                 calc_l4_cksm ? BPF_F_ADJ_ROOM_NO_CSUM_RESET
                                              : 0))) {
    bpf_printk("UDP ADJUST ROOM(decap): %d", ret);
    return ret;
  }

  // Rewrite ip len.
  if (ipversion == 4) {
    if ((ret = adjust_ipv4_len(skb, ipv4hdr_tot_len, -decap_hdrlen))) {
      bpf_printk("adjust_ip_len: %d", ret);
      return ret;
    }
  }

  // Rewrite udp len.
  if ((ret = adjust_udp_len(skb, reserved_udphdr.len, ihl, -decap_hdrlen,
                            calc_l4_cksm))) {
    bpf_printk("adjust_udp_len: %d", ret);
    return ret;
  }

  // Rewrite udp checksum.
  if (calc_l4_cksm) {
    __u32 udp_csum_off = l4_checksum_off(IPPROTO_UDP, ihl);
    __s64 cksm = bpf_csum_diff(to, decap_hdrlen, 0, 0, 0);
    if ((ret = bpf_l4_csum_replace(skb, udp_csum_off, 0, cksm,
                                   BPF_F_MARK_MANGLED_0))) {
      bpf_printk("bpf_l4_csum_replace 2: %d", ret);
      return ret;
    }
  }
  return 0;
}

// Do not use __always_inline here because this function is too heavy.
static int __attribute__((noinline))
routing(const __u32 flag[6], const void *l4hdr, const __be32 saddr[4],
        const __be32 _daddr[4], const __be32 mac[4]) {
#define _l4proto_type flag[0]
#define _ipversion_type flag[1]
#define _pname &flag[2]
#define _is_wan flag[2]

  int ret;
  struct lpm_key lpm_key_instance, *lpm_key;
  __u32 key = MatchType_L4Proto;
  __u16 h_dport;
  __u16 h_sport;
  __u32 daddr[4];

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

  // Modify DNS upstream for routing.
  if (h_dport == 53 && _l4proto_type == L4ProtoType_UDP) {
    struct ip_port *upstream =
        bpf_map_lookup_elem(&dns_upstream_map, &zero_key);
    if (upstream && upstream->port != 0) {
      h_dport = bpf_ntohs(upstream->port);
      __builtin_memcpy(daddr, upstream->ip, IPV6_BYTE_LENGTH);
    } else {
      __builtin_memcpy(daddr, _daddr, IPV6_BYTE_LENGTH);
    }
  } else {
    __builtin_memcpy(daddr, _daddr, IPV6_BYTE_LENGTH);
  }
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
  if (!_is_wan) {
    __builtin_memcpy(lpm_key_instance.data, mac, IPV6_BYTE_LENGTH);
    key = MatchType_Mac;
    if (unlikely((ret = bpf_map_update_elem(&lpm_key_map, &key,
                                            &lpm_key_instance, BPF_ANY)))) {
      return ret;
    };
  }

  struct map_lpm_type *lpm;
  struct match_set *match_set;
  // Rule is like: domain(suffix:baidu.com, suffix:google.com) && port(443) ->
  // proxy Subrule is like: domain(suffix:baidu.com, suffix:google.com) Match
  // set is like: suffix:baidu.com
  bool bad_rule = false;
  bool good_subrule = false;
  struct domain_routing *domain_routing;
  __u32 *p_u32;
  __u16 *p_u16;

#pragma unroll
  for (__u32 i = 0; i < MAX_MATCH_SET_LEN; i++) {
    __u32 k = i; // Clone to pass code checker.
    match_set = bpf_map_lookup_elem(&routing_map, &k);
    if (unlikely(!match_set)) {
      return -EFAULT;
    }
    if (bad_rule || good_subrule) {
#ifdef __DEBUG_ROUTING
      key = match_set->type;
      bpf_printk("key(match_set->type): %llu", key);
      bpf_printk("Skip to judge. bad_rule: %d, good_subrule: %d", bad_rule,
                 good_subrule);
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
        good_subrule = true;
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
        good_subrule = true;
      }
    } else if ((p_u32 = bpf_map_lookup_elem(&l4proto_ipversion_map, &key))) {
#ifdef __DEBUG_ROUTING
      bpf_printk("CHECK: l4proto_ipversion_map, match_set->type: %u, not: %d, "
                 "outbound: %u",
                 match_set->type, match_set->not, match_set->outbound);
#endif
      if (*p_u32 & *(__u32 *)&match_set->__value) {
        good_subrule = true;
      }
    } else if (match_set->type == MatchType_DomainSet) {
#ifdef __DEBUG_ROUTING
      bpf_printk("CHECK: domain, match_set->type: %u, not: %d, "
                 "outbound: %u",
                 match_set->type, match_set->not, match_set->outbound);
#endif

      // Get domain routing bitmap.
      domain_routing = bpf_map_lookup_elem(&domain_routing_map, daddr);
      if (!domain_routing) {
        // No domain corresponding to IP.
        goto before_next_loop;
      }

      // We use key instead of k to pass checker.
      if ((domain_routing->bitmap[i / 32] >> (i % 32)) & 1) {
        good_subrule = true;
      }
    } else if (match_set->type == MatchType_ProcessName) {
      if (_is_wan && equal16(match_set->pname, _pname)) {
        good_subrule = true;
      }
    } else if (match_set->type == MatchType_Final) {
#ifdef __DEBUG_ROUTING
      bpf_printk("CHECK: hit final");
#endif
      good_subrule = true;
    } else {
#ifdef __DEBUG_ROUTING
      bpf_printk("CHECK: <unknown>, match_set->type: %u, not: %d, "
                 "outbound: %u",
                 match_set->type, match_set->not, match_set->outbound);
#endif
      return -EINVAL;
    }

  before_next_loop:
#ifdef __DEBUG_ROUTING
    bpf_printk("good_subrule: %d, bad_rule: %d", good_subrule, bad_rule);
#endif
    if (match_set->outbound != OUTBOUND_LOGICAL_OR) {
      // This match_set reaches the end of subrule.
      // We are now at end of rule, or next match_set belongs to another
      // subrule.

      if (good_subrule == match_set->not ) {
        // This subrule does not hit.
        bad_rule = true;
      }

      // Reset good_subrule.
      good_subrule = false;
    }
#ifdef __DEBUG_ROUTING
    bpf_printk("_bad_rule: %d", bad_rule);
#endif
    if ((match_set->outbound & OUTBOUND_LOGICAL_MASK) !=
        OUTBOUND_LOGICAL_MASK) {
      // Tail of a rule (line).
      // Decide whether to hit.
      if (!bad_rule) {
#ifdef __DEBUG_ROUTING
        bpf_printk("MATCHED: match_set->type: %u, match_set->not: %d",
                   match_set->type, match_set->not );
#endif
        if (match_set->outbound == OUTBOUND_DIRECT && h_dport == 53 &&
            _l4proto_type == L4ProtoType_UDP) {
          // DNS packet should go through control plane.
          return OUTBOUND_CONTROL_PLANE_DIRECT;
        }
        return match_set->outbound;
      }
      bad_rule = false;
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

SEC("tc/ingress")
int tproxy_lan_ingress(struct __sk_buff *skb) {
  struct ethhdr ethh;
  struct iphdr iph;
  struct ipv6hdr ipv6h;
  struct tcphdr tcph;
  struct udphdr udph;
  __u8 ihl;
  __u8 ipversion;
  __u8 l4proto;
  int ret = parse_transport(skb, &ethh, &iph, &ipv6h, &tcph, &udph, &ihl,
                            &ipversion, &l4proto);
  if (ret) {
    bpf_printk("parse_transport: %d", ret);
    return TC_ACT_OK;
  }

  // Prepare five tuples.
  struct tuples tuples = {0};
  tuples.l4proto = l4proto;
  if (ipversion == 4) {
    tuples.src.ip[2] = bpf_htonl(0x0000ffff);
    tuples.src.ip[3] = iph.saddr;

    tuples.dst.ip[2] = bpf_htonl(0x0000ffff);
    tuples.dst.ip[3] = iph.daddr;

  } else {
    __builtin_memcpy(tuples.dst.ip, &ipv6h.daddr, IPV6_BYTE_LENGTH);
    __builtin_memcpy(tuples.src.ip, &ipv6h.saddr, IPV6_BYTE_LENGTH);
  }
  if (l4proto == IPPROTO_TCP) {
    tuples.src.port = tcph.source;
    tuples.dst.port = tcph.dest;
  } else {
    tuples.src.port = udph.source;
    tuples.dst.port = udph.dest;
  }

  /**
  ip rule add fwmark 0x80000000/0x80000000 table 2023
  ip route add local default dev lo table 2023
  ip -6 rule add fwmark 0x80000000/0x80000000 table 2023
  ip -6 route add local ::/0 dev lo table 2023

  ip rule del fwmark 0x80000000/0x80000000 table 2023
  ip route del local default dev lo table 2023
  ip -6 rule del fwmark 0x80000000/0x80000000 table 2023
  ip -6 route del local ::/0 dev lo table 2023
  */
  struct bpf_sock_tuple tuple = {0};
  __u32 tuple_size;
  struct bpf_sock *sk;
  bool is_old_conn = false;
  __u32 flag[6] = {0};
  void *l4hdr;

  // Socket lookup and assign skb to existing socket connection.
  if (ipversion == 4) {
    tuple.ipv4.daddr = tuples.dst.ip[3];
    tuple.ipv4.saddr = tuples.src.ip[3];
    tuple.ipv4.dport = tuples.dst.port;
    tuple.ipv4.sport = tuples.src.port;
    tuple_size = sizeof(tuple.ipv4);
  } else {
    __builtin_memcpy(tuple.ipv6.daddr, tuples.dst.ip, IPV6_BYTE_LENGTH);
    __builtin_memcpy(tuple.ipv6.saddr, tuples.src.ip, IPV6_BYTE_LENGTH);
    tuple.ipv6.dport = tuples.dst.port;
    tuple.ipv6.sport = tuples.src.port;
    tuple_size = sizeof(tuple.ipv6);
  }

  if (l4proto == IPPROTO_TCP) {
    // TCP.
    if (tcph.syn && !tcph.ack) {
      goto new_connection;
    }

    sk = bpf_skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);
    if (sk) {
      if (sk->state != BPF_TCP_LISTEN) {
        is_old_conn = true;
        goto assign;
      }
      bpf_sk_release(sk);
    }
  } else {
    // UDP.

    sk = bpf_sk_lookup_udp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);
    if (sk) {
      is_old_conn = true;
      goto assign;
    }
  }

// Routing for new connection.
new_connection:
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
  if (ipversion == 4) {
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
  if ((ret = routing(flag, l4hdr, tuples.src.ip, tuples.dst.ip, mac)) < 0) {
    bpf_printk("shot routing: %d", ret);
    return TC_ACT_SHOT;
  }
  __u32 outbound = ret;
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
  if (l4proto == IPPROTO_TCP) {
    bpf_printk("tcp(lan): outbound: %u, target: %pI6:%u", outbound,
               tuples.dst.ip, bpf_ntohs(tuples.dst.port));
  } else {
    bpf_printk("udp(lan): outbound: %u, target: %pI6:%u", outbound,
               tuples.dst.ip, bpf_ntohs(tuples.dst.port));
  }
#endif
  if (outbound == OUTBOUND_DIRECT) {
    goto direct;
  } else if (unlikely(outbound == OUTBOUND_BLOCK)) {
    goto block;
  }

  // Save routing result.
  if ((ret = bpf_map_update_elem(&routing_tuples_map, &tuples, &outbound,
                                 BPF_ANY))) {
    bpf_printk("shot save routing result: %d", ret);
    return TC_ACT_SHOT;
  }

  // Assign to control plane.

  if (l4proto == IPPROTO_TCP) {
    // TCP.
    sk = bpf_map_lookup_elem(&listen_socket_map, &zero_key);
    if (!sk || sk->state != BPF_TCP_LISTEN) {
      bpf_printk("shot tcp tproxy not listen: %d", ret);
      goto sk_shot;
    }
  } else {
    // UDP.

    sk = bpf_map_lookup_elem(&listen_socket_map, &one_key);
    if (!sk) {
      bpf_printk("shot udp tproxy not listen: %d", ret);
      goto sk_shot;
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

sk_shot:
  if (sk) {
    bpf_sk_release(sk);
  }
  return TC_ACT_SHOT;

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

static __always_inline bool wan_disable_checksum(const __u32 ifindex,
                                                 const __u8 ipversion) {

  struct if_params *ifparams =
      bpf_map_lookup_elem(&ifindex_params_map, &ifindex);
  if (unlikely(!ifparams)) {
    return -1;
  }
  bool tx_offloaded = (ipversion == 4 && ifparams->tx_l4_cksm_ip4_offload) ||
                      (ipversion == 6 && ifparams->tx_l4_cksm_ip6_offload);
  // If tx offloaded, we get bad checksum of packets because we redirect packet
  // before the NIC processing. So we have no choice but disable l4 checksum.

  bool disable_l4_checksum = tx_offloaded;

  return disable_l4_checksum;
}

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
  struct tcphdr tcph;
  struct udphdr udph;
  __u8 ihl;
  __u8 ipversion;
  __u8 l4proto;
  bool tcp_state_syn;
  int ret = parse_transport(skb, &ethh, &iph, &ipv6h, &tcph, &udph, &ihl,
                            &ipversion, &l4proto);
  if (ret) {
    return TC_ACT_OK;
  }

  __be16 sport;
  if (l4proto == IPPROTO_TCP) {
    sport = tcph.source;
  } else if (l4proto == IPPROTO_UDP) {
    sport = udph.source;
  } else {
    return TC_ACT_OK;
  }

  // We should know if this packet is from tproxy.
  // We do not need to check the source ip because we have skipped packets not
  // from localhost.
  __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
  if (!tproxy_port) {
    return TC_ACT_OK;
  }
  bool tproxy_response = *tproxy_port == sport;

  // Backup for further use.
  __be16 ipv4_tot_len = 0;

  // Parse saddr and daddr as ipv6 format.
  __be32 saddr[4];
  __be32 daddr[4];
  if (ipversion == 4) {
    saddr[0] = 0;
    saddr[1] = 0;
    saddr[2] = bpf_htonl(0x0000ffff);
    saddr[3] = iph.saddr;

    daddr[0] = 0;
    daddr[1] = 0;
    daddr[2] = bpf_htonl(0x0000ffff);
    daddr[3] = iph.daddr;

    ipv4_tot_len = iph.tot_len;
  } else {
    __builtin_memcpy(daddr, &ipv6h.daddr, IPV6_BYTE_LENGTH);
    __builtin_memcpy(saddr, &ipv6h.saddr, IPV6_BYTE_LENGTH);
  }

  if (tproxy_response) {
    // Packets from tproxy port.
    // We need to redirect it to original port.

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
      __builtin_memcpy(key_src.ip, daddr, IPV6_BYTE_LENGTH);
      key_src.port = tcph.source;
      __u8 outbound;
      if (unlikely(tcp_state_syn)) {
        // New TCP connection.
        // bpf_printk("[%X]New Connection", bpf_ntohl(tcph.seq));
        __u32 flag[6] = {L4ProtoType_TCP}; // TCP
        if (ipversion == 6) {
          flag[1] = IpVersionType_6;
        } else {
          flag[1] = IpVersionType_4;
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
        if ((ret = routing(flag, &tcph, saddr, daddr, mac)) < 0) {
          bpf_printk("shot routing: %d", ret);
          return TC_ACT_SHOT;
        }

        outbound = ret;

#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
        // Print only new connection.
        bpf_printk("tcp(wan): outbound: %u, %pI6:%u", outbound, daddr,
                   bpf_ntohs(key_src.port));
#endif
      } else {
        // bpf_printk("[%X]Old Connection", bpf_ntohl(tcph.seq));
        // The TCP connection exists.
        struct ip_port_outbound *dst =
            bpf_map_lookup_elem(&tcp_dst_map, &key_src);
        if (!dst) {
          // Do not impact previous connections.
          return TC_ACT_OK;
        }
        outbound = dst->outbound;
      }

      if (outbound == OUTBOUND_DIRECT) {
        return TC_ACT_OK;
      } else if (unlikely(outbound == OUTBOUND_BLOCK)) {
        return TC_ACT_SHOT;
      }
      // Rewrite to control plane.

      if (unlikely(tcp_state_syn)) {
        struct ip_port_outbound value_dst;
        __builtin_memset(&value_dst, 0, sizeof(value_dst));
        __builtin_memcpy(value_dst.ip, daddr, IPV6_BYTE_LENGTH);
        value_dst.port = tcph.dest;
        value_dst.outbound = outbound;
        // bpf_printk("UPDATE: %pI6:%u", key_src.ip, bpf_ntohs(key_src.port));
        bpf_map_update_elem(&tcp_dst_map, &key_src, &value_dst, BPF_ANY);
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
      // Backup for further use.
      struct ip_port_outbound new_hdr;
      __builtin_memset(&new_hdr, 0, sizeof(new_hdr));
      __builtin_memcpy(new_hdr.ip, daddr, IPV6_BYTE_LENGTH);
      new_hdr.port = udph.dest;

      // Routing. It decides if we redirect traffic to control plane.
      __u32 flag[6] = {L4ProtoType_UDP};
      if (ipversion == 6) {
        flag[1] = IpVersionType_6;
      } else {
        flag[1] = IpVersionType_4;
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
      if ((ret = routing(flag, &udph, saddr, daddr, mac)) < 0) {
        bpf_printk("shot routing: %d", ret);
        return TC_ACT_SHOT;
      }
      new_hdr.outbound = ret;
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
      bpf_printk("udp(wan): outbound: %u, %pI6:%u", new_hdr.outbound, daddr,
                 bpf_ntohs(new_hdr.port));
#endif

      if (new_hdr.outbound == OUTBOUND_DIRECT) {
        return TC_ACT_OK;
      } else if (unlikely(new_hdr.outbound == OUTBOUND_BLOCK)) {
        return TC_ACT_SHOT;
      }

      // Rewrite to control plane.

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

      bool disable_l4_checksum = wan_disable_checksum(skb->ifindex, ipversion);
      // Encap a header to transmit fullcone tuple.
      if ((ret = encap_after_udp_hdr(skb, ipversion, ihl, ipv4_tot_len,
                                     &new_hdr, sizeof(new_hdr),
                                     // It is a part of ingress link.
                                     !disable_l4_checksum))) {
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
  struct tcphdr tcph;
  struct udphdr udph;
  __u8 ihl;
  __u8 ipversion;
  __u8 l4proto;
  int ret = parse_transport(skb, &ethh, &iph, &ipv6h, &tcph, &udph, &ihl,
                            &ipversion, &l4proto);
  if (ret) {
    return TC_ACT_OK;
  }

  // bpf_printk("bpf_ntohs(*(__u16 *)&ethh.h_source[4]): %u",
  //            bpf_ntohs(*(__u16 *)&ethh.h_source[4]));
  // Tproxy related.
  __u16 tproxy_typ = bpf_ntohs(*(__u16 *)&ethh.h_source[4]);
  if (*(__u32 *)&ethh.h_source[0] != bpf_htonl(0x02000203) || tproxy_typ > 1) {
    return TC_ACT_OK;
  }
  bool tproxy_response = tproxy_typ == 1;

  // Parse saddr and daddr as ipv6 format.
  __be32 saddr[4];
  __be32 daddr[4];
  __be32 ipv4_tot_len = 0;
  if (ipversion == 4) {
    saddr[0] = 0;
    saddr[1] = 0;
    saddr[2] = bpf_htonl(0x0000ffff);
    saddr[3] = iph.saddr;

    daddr[0] = 0;
    daddr[1] = 0;
    daddr[2] = bpf_htonl(0x0000ffff);
    daddr[3] = iph.daddr;

    ipv4_tot_len = iph.tot_len;
  } else {
    __builtin_memcpy(daddr, &ipv6h.daddr, IPV6_BYTE_LENGTH);
    __builtin_memcpy(saddr, &ipv6h.saddr, IPV6_BYTE_LENGTH);
  }
  __be16 sport;
  __be16 dport;
  if (l4proto == IPPROTO_TCP) {
    sport = tcph.source;
    dport = tcph.dest;
  } else if (l4proto == IPPROTO_UDP) {
    sport = udph.source;
    dport = udph.dest;
  } else {
    return TC_ACT_OK;
  }

  bool disable_l4_checksum = wan_disable_checksum(skb->ifindex, ipversion);

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
      __builtin_memcpy(key_dst.ip, daddr, IPV6_BYTE_LENGTH);
      key_dst.port = tcph.dest;
      struct ip_port_outbound *original_dst =
          bpf_map_lookup_elem(&tcp_dst_map, &key_dst);
      if (!original_dst) {
        bpf_printk("[%X]Bad Connection: to: %pI6:%u", bpf_ntohl(tcph.seq),
                   key_dst.ip, bpf_ntohs(key_dst.port));
        // Do not impact previous connections.
        return TC_ACT_SHOT;
      }

      // Rewrite sip and sport.
      if ((ret = rewrite_ip(skb, ipversion, IPPROTO_TCP, ihl, saddr,
                            original_dst->ip, false, !disable_l4_checksum))) {
        bpf_printk("Shot IP: %d", ret);
        return TC_ACT_SHOT;
      }
      if ((ret = rewrite_port(skb, IPPROTO_TCP, ihl, sport, original_dst->port,
                              false, !disable_l4_checksum))) {
        bpf_printk("Shot Port: %d", ret);
        return TC_ACT_SHOT;
      }
    } else if (l4proto == IPPROTO_UDP) {

      /// NOTICE: Actually, we do not need symmetrical headers in client and
      /// server. We use it for convinience. This behavior may change in the
      /// future. Outbound here is useless and redundant.
      struct ip_port_outbound ori_src;

      // Get source ip/port from our packet header.

      // Decap header to get fullcone tuple.
      if ((ret =
               decap_after_udp_hdr(skb, ipversion, ihl, ipv4_tot_len, &ori_src,
                                   sizeof(ori_src), !disable_l4_checksum))) {
        return TC_ACT_SHOT;
      }

      // Rewrite udp src ip
      if ((ret = rewrite_ip(skb, ipversion, IPPROTO_UDP, ihl, saddr, ori_src.ip,
                            false, !disable_l4_checksum))) {
        bpf_printk("Shot IP: %d", ret);
        return TC_ACT_SHOT;
      }

      // Rewrite udp src port
      if ((ret = rewrite_port(skb, IPPROTO_UDP, ihl, sport, ori_src.port, false,
                              !disable_l4_checksum))) {
        bpf_printk("Shot Port: %d", ret);
        return TC_ACT_SHOT;
      }

      // bpf_printk("real from: %pI4:%u", &ori_src.ip, bpf_ntohs(ori_src.port));

      // Print packet in hex for debugging (checksum or something else).
      // bpf_printk("UDP EGRESS OK");
      // for (__u32 i = 0; i < skb->len && i < 1500; i++) {
      //   __u8 t = 0;
      //   bpf_skb_load_bytes(skb, i, &t, 1);
      //   bpf_printk("%02x", t);
      // }
    }
    // Rewrite dip to host ip.
    if ((ret = rewrite_ip(skb, ipversion, l4proto, ihl, daddr, saddr, true,
                          !disable_l4_checksum))) {
      bpf_printk("Shot IP: %d", ret);
      return TC_ACT_SHOT;
    }
  } else {
    // Should send the packet to tproxy.

    // Get tproxy ip and port.
    // saddr should be tproxy ip.
    __be32 *tproxy_ip = saddr;
    // __builtin_memcpy(tproxy_ip, saddr, sizeof(tproxy_ip));
    __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
    if (!tproxy_port) {
      return TC_ACT_OK;
    }
    // bpf_printk("should send to: %pI6:%u", tproxy_ip,
    // bpf_ntohs(*tproxy_port));

    if ((ret = rewrite_ip(skb, ipversion, l4proto, ihl, daddr, tproxy_ip, true,
                          !disable_l4_checksum))) {
      bpf_printk("Shot IP: %d", ret);
      return TC_ACT_SHOT;
    }

    // Rewrite dst port.
    if ((ret = rewrite_port(skb, l4proto, ihl, dport, *tproxy_port, true,
                            !disable_l4_checksum))) {
      bpf_printk("Shot Port: %d", ret);
      return TC_ACT_SHOT;
    }

    // (1) Use daddr as saddr to pass NIC verification. Notice that we do not
    // modify the <sport> so tproxy will send packet to it.
    if ((ret = rewrite_ip(skb, ipversion, l4proto, ihl, saddr, daddr, false,
                          !disable_l4_checksum))) {
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
  if (disable_l4_checksum) {
    __u32 l4_cksm_off = l4_checksum_off(l4proto, ihl);
    // Set checksum zero.
    __sum16 bak_cksm = 0;
    bpf_skb_store_bytes(skb, l4_cksm_off, &bak_cksm, sizeof(bak_cksm), 0);
    bpf_csum_level(skb, BPF_CSUM_LEVEL_RESET);
  }

  return TC_ACT_OK;
}

static int __always_inline update_map_elem_by_cookie(const __u64 cookie) {
  if (unlikely(!cookie)) {
    bpf_printk("zero cookie");
    return -EINVAL;
  }
  int ret;

  // Build value.
  struct pid_pname val;
  __builtin_memset(&val, 0, sizeof(struct pid_pname));
  char buf[MAX_ARG_SCANNER_BUFFER_SIZE] = {0};
  struct task_struct *current = (void *)bpf_get_current_task();
  unsigned long arg_start = BPF_PROBE_READ_KERNEL(current, mm, arg_start);
  unsigned long arg_end = BPF_PROBE_READ_KERNEL(current, mm, arg_end);
  unsigned long arg_len = arg_end - arg_start;
  if (arg_len > MAX_ARG_LEN_TO_PROBE) {
    arg_len = MAX_ARG_LEN_TO_PROBE;
  }

  /**
  For string like: /usr/lib/sddm/sddm-helper --socket /tmp/sddm-auth1
  We extract "sddm-helper" from it.
  */
  unsigned long loc, j;
  unsigned long last_slash = -1;
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
      // No need to CO-RE.
      if ((ret = bpf_probe_read_user(&buf, to_read,
                                     (const void *)(arg_start + j)))) {
        bpf_printk("failed to read process name: %d", ret);
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
  if ((ret = bpf_probe_read_user(&val.pname, length_cpy,
                                 (const void *)(arg_start + last_slash)))) {
    bpf_printk("failed to read process name: %d", ret);
    return ret;
  }
  bpf_probe_read_kernel(&val.pid, sizeof(val.pid), &current->tgid);
  // bpf_printk("a start_end: %lu %lu", arg_start, arg_end);
  // bpf_printk("b start_end: %lu %lu", arg_start + last_slash, arg_start + j);

  // Update map.
  if (unlikely(ret = bpf_map_update_elem(&cookie_pid_map, &cookie, &val,
                                         BPF_NOEXIST))) {
    // bpf_printk("setup_mapping_from_sk: failed update map: %d", ret);
    return ret;
  }

  bpf_printk("setup_mapping: %llu -> %s (%d)", cookie, val.pname, val.pid);
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

SEC("license") const char __license[] = "Dual BSD/GPL";
