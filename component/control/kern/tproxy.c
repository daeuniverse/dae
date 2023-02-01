// +build ignore
/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */
#include "headers/if_ether_defs.h"
#include "headers/pkt_cls_defs.h"
#include "headers/socket_defs.h"
#include "headers/vmlinux.h"

#include <asm-generic/errno-base.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

#define MAX_PARAM_LEN 16
#define MAX_INTERFACE_NUM 128
#define MAX_MATCH_SET_LEN (32 * 3)
#define MAX_LPM_SIZE 20480
//#define MAX_LPM_SIZE 20480
#define MAX_LPM_NUM (MAX_MATCH_SET_LEN + 8)
#define MAX_DST_MAPPING_NUM (65536 * 2)
#define MAX_SRC_PID_PNAME_MAPPING_NUM (65536)
#define IPV6_MAX_EXTENSIONS 4

#define OUTBOUND_DIRECT 0
#define OUTBOUND_BLOCK 1
#define OUTBOUND_CONTROL_PLANE_DIRECT 0xFD
#define OUTBOUND_LOGICAL_OR 0xFE
#define OUTBOUND_LOGICAL_AND 0xFF
#define OUTBOUND_LOGICAL_MASK 0xFE

/* Current network namespace */
enum {
  BPF_F_CURRENT_NETNS = (-1L),
};

enum {
  DisableL4ChecksumPolicy_EnableL4Checksum,
  DisableL4ChecksumPolicy_Restore,
  DisableL4ChecksumPolicy_SetZero,
};

// Param keys:
static const __u32 zero_key = 0;
static const __u32 tproxy_port_key = 1;
static const __u32 disable_l4_tx_checksum_key = 2;
static const __u32 disable_l4_rx_checksum_key = 3;
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
struct if_ip {
  __be32 ip4[4];
  __be32 ip6[4];
  bool hasIp4;
  bool hasIp6;
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);          // ifindex
  __type(value, struct if_ip); // ip
  __uint(max_entries, MAX_INTERFACE_NUM);
  /// NOTICE: No persistence.
  // __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifindex_tproxy_ip_map SEC(".maps");

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
    __u32 __value; // Placeholder for bpf2go.

    __u32 index;
    struct port_range port_range;
    enum L4ProtoType l4proto_type;
    enum IpVersionType ip_version;
    __u32 pname[TASK_COMM_LEN / 4];
  };
  enum MatchType type;
  bool not ;     // A subrule flag (this is not a match_set flag).
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
  __type(key, struct ip_port_proto);
  __type(value, struct pid_pname);
  __uint(max_entries, MAX_SRC_PID_PNAME_MAPPING_NUM);
  /// NOTICE: No persistence.
  // __uint(pinning, LIBBPF_PIN_BY_NAME);
} src_pid_map SEC(".maps");

// Functions:

static __always_inline bool equal_ipv6_format(__be32 x[4], __be32 y[4]) {
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

static __always_inline int rewrite_ip(struct __sk_buff *skb, __u8 ipversion,
                                      __u8 proto, __u8 ihl, __be32 old_ip[4],
                                      __be32 new_ip[4], bool is_dest) {
  // Nothing to do.
  if (equal_ipv6_format(old_ip, new_ip)) {
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

    if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, _old_ip, _new_ip,
                                   l4flags | sizeof(_new_ip)))) {
      bpf_printk("bpf_l4_csum_replace: %d", ret);
      return ret;
    }

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
    __s64 cksm =
        bpf_csum_diff(new_ip, IPV6_BYTE_LENGTH, old_ip, IPV6_BYTE_LENGTH, 0);
    if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, 0, cksm, l4flags))) {
      bpf_printk("bpf_l4_csum_replace: %d", ret);
      return ret;
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
                                        __be16 new_port, bool is_dest) {
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
  }

  // bpf_printk("%u -> %u", bpf_ntohs(old_port), bpf_ntohs(new_port));

  int ret;
  if ((ret = bpf_l4_csum_replace(skb, cksm_off, old_port, new_port,
                                 l4flags | sizeof(new_port)))) {
    bpf_printk("bpf_l4_csum_replace: %d", ret);
    return ret;
  }
  ret = bpf_skb_store_bytes(skb, port_off, &new_port, sizeof(new_port), 0);

  if (ret) {
    return ret;
  }

  return 0;
}

static __always_inline int handle_ipv6_extensions(struct __sk_buff *skb,
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
      // Unknown hdr.
      return 1;
    }
  }
  bpf_printk("exceeds IPV6_MAX_EXTENSIONS limit");
  return 1;
}

static __always_inline int
parse_transport(struct __sk_buff *skb, struct ethhdr *ethh, struct iphdr *iph,
                struct ipv6hdr *ipv6h, struct tcphdr *tcph, struct udphdr *udph,
                __u8 *ihl, __u8 *ipversion, __u8 *l4proto) {

  __u32 offset = 0;
  int ret = bpf_skb_load_bytes(skb, offset, ethh, sizeof(struct ethhdr));
  if (ret) {
    bpf_printk("not ethernet packet");
    return 1;
  }
  // Skip ethhdr for next hdr.
  offset += sizeof(struct ethhdr);

  __builtin_memset(iph, 0, sizeof(struct iphdr));
  __builtin_memset(ipv6h, 0, sizeof(struct ipv6hdr));
  __builtin_memset(tcph, 0, sizeof(struct tcphdr));
  __builtin_memset(udph, 0, sizeof(struct udphdr));
  *ihl = 0;
  *ipversion = 0;
  *l4proto = 0;

  // bpf_printk("parse_transport: h_proto: %u ? %u %u", eth->h_proto,
  //            bpf_htons(ETH_P_IP), bpf_htons(ETH_P_IPV6));
  if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
    *ipversion = 4;

    if ((ret = bpf_skb_load_bytes(skb, offset, iph, sizeof(struct iphdr)))) {
      return -EFAULT;
    }
    // Skip ipv4hdr and options for next hdr.
    offset += iph->ihl * 4;

    // We only process TCP and UDP traffic.
    *l4proto = iph->protocol;
    if (iph->protocol == IPPROTO_TCP) {
      if ((ret =
               bpf_skb_load_bytes(skb, offset, tcph, sizeof(struct tcphdr)))) {
        // Not a complete tcphdr.
        return -EFAULT;
      }
    } else if (iph->protocol == IPPROTO_UDP) {
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
    *ipversion = 6;

    if ((ret =
             bpf_skb_load_bytes(skb, offset, ipv6h, sizeof(struct ipv6hdr)))) {
      bpf_printk("not a valid IPv6 packet");
      return -EFAULT;
    }

    offset += sizeof(struct ipv6hdr);

    return handle_ipv6_extensions(skb, offset, ipv6h->nexthdr, tcph, udph, ihl,
                                  l4proto);
  }
  return 1;
}

static __always_inline int get_tproxy_ip(__u8 ipversion, __u32 ifindex,
                                         __be32 tproxy_ip[4]) {
  struct if_ip *if_ip = bpf_map_lookup_elem(&ifindex_tproxy_ip_map, &ifindex);
  if (unlikely(!if_ip)) {
    return -1;
  }
  if (ipversion == 4 && (*if_ip).hasIp4) {
    __builtin_memcpy(tproxy_ip, (*if_ip).ip4, IPV6_BYTE_LENGTH);
  } else if (ipversion == 6 && (*if_ip).hasIp6) {
    __builtin_memcpy(tproxy_ip, (*if_ip).ip6, IPV6_BYTE_LENGTH);
  } else {
    // Should TC_ACT_OK outer.
    return -EFAULT;
  }
  return 0;
}

static __always_inline int ip_is_host(__u8 ipversion, __u32 ifindex,
                                      __be32 ip[4], __be32 tproxy_ip[4]) {
  if (tproxy_ip) {
    int ret;
    if ((ret = get_tproxy_ip(ipversion, ifindex, tproxy_ip))) {
      return ret;
    }
  }

  struct lpm_key lpm_key;
  lpm_key.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
  __builtin_memcpy(lpm_key.data, ip, IPV6_BYTE_LENGTH);
  return bpf_map_lookup_elem(&host_ip_lpm, &lpm_key) ? 1 : 0;
}

static __always_inline int adjust_udp_len(struct __sk_buff *skb, __u16 oldlen,
                                          __u32 ihl, __u16 len_diff) {
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
                                               void *newhdr, __u32 newhdrlen) {
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
  __builtin_memset(&reserved_udphdr, 0, sizeof(reserved_udphdr));
  if ((ret = bpf_skb_load_bytes(skb, ip_off + ipp_len, &reserved_udphdr,
                                sizeof(reserved_udphdr)))) {
    bpf_printk("bpf_skb_load_bytes: %d", ret);
    return ret;
  }
  // Add room for new udp payload header.
  if ((ret = bpf_skb_adjust_room(skb, newhdrlen, BPF_ADJ_ROOM_NET, 0))) {
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
  if ((ret = adjust_udp_len(skb, reserved_udphdr.len, ihl, newhdrlen))) {
    bpf_printk("adjust_udp_len: %d", ret);
    return ret;
  }

  // Rewrite udp payload.
  __u32 l4_cksm_off = l4_checksum_off(IPPROTO_UDP, ihl);
  __s64 cksm = bpf_csum_diff(NULL, 0, newhdr, newhdrlen, 0);
  if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, 0, cksm,
                                 BPF_F_MARK_MANGLED_0))) {
    bpf_printk("bpf_l4_csum_replace 2: %d", ret);
    return ret;
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
                                               __u32 decap_hdrlen) {
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
  __builtin_memset(&reserved_udphdr, 0, sizeof(reserved_udphdr));
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
  if ((ret = bpf_skb_adjust_room(skb, -decap_hdrlen, BPF_ADJ_ROOM_NET, 0))) {
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
  if ((ret = adjust_udp_len(skb, reserved_udphdr.len, ihl, -decap_hdrlen))) {
    bpf_printk("adjust_udp_len: %d", ret);
    return ret;
  }

  // Rewrite udp checksum.
  __u32 udp_csum_off = l4_checksum_off(IPPROTO_UDP, ihl);
  __s64 cksm = bpf_csum_diff(to, decap_hdrlen, 0, 0, 0);
  if ((ret = bpf_l4_csum_replace(skb, udp_csum_off, 0, cksm,
                                 BPF_F_MARK_MANGLED_0))) {
    bpf_printk("bpf_l4_csum_replace 2: %d", ret);
    return ret;
  }
  return 0;
}

// Do not use __always_inline here because this function is too heavy.
static int routing(__u32 flag[6], void *l4_hdr, __be32 saddr[4],
                   __be32 daddr[4], __be32 mac[4]) {
#define _l4proto_type flag[0]
#define _ipversion_type flag[1]
#define _pname &flag[2]

  int ret;

  /// TODO: BPF_MAP_UPDATE_BATCH ?
  __u32 key = MatchType_L4Proto;
  if ((ret = bpf_map_update_elem(&l4proto_ipversion_map, &key, &_l4proto_type,
                                 BPF_ANY))) {
    return ret;
  };
  key = MatchType_IpVersion;
  if ((ret = bpf_map_update_elem(&l4proto_ipversion_map, &key, &_ipversion_type,
                                 BPF_ANY))) {
    return ret;
  };

  // Define variables for further use.
  __u16 h_dport;
  __u16 h_sport;
  if (_l4proto_type == L4ProtoType_TCP) {
    h_dport = bpf_ntohs(((struct tcphdr *)l4_hdr)->dest);
    h_sport = bpf_ntohs(((struct tcphdr *)l4_hdr)->source);
  } else {
    h_dport = bpf_ntohs(((struct udphdr *)l4_hdr)->dest);
    h_sport = bpf_ntohs(((struct udphdr *)l4_hdr)->source);
  }

  key = MatchType_SourcePort;
  if ((ret = bpf_map_update_elem(&h_port_map, &key, &h_sport, BPF_ANY))) {
    return ret;
  };
  key = MatchType_Port;
  if ((ret = bpf_map_update_elem(&h_port_map, &key, &h_dport, BPF_ANY))) {
    return ret;
  };

  // Modify DNS upstream for routing.
  if (h_dport == 53 && _l4proto_type == L4ProtoType_UDP) {
    struct ip_port *upstream =
        bpf_map_lookup_elem(&dns_upstream_map, &zero_key);
    if (!upstream) {
      return -EFAULT;
    }
    h_dport = bpf_ntohs(upstream->port);
    __builtin_memcpy(daddr, upstream->ip, IPV6_BYTE_LENGTH);
  }
  struct lpm_key lpm_key_saddr, lpm_key_daddr, lpm_key_mac, *lpm_key;
  lpm_key_saddr.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
  lpm_key_daddr.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
  lpm_key_mac.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
  __builtin_memcpy(lpm_key_saddr.data, saddr, IPV6_BYTE_LENGTH);
  __builtin_memcpy(lpm_key_daddr.data, daddr, IPV6_BYTE_LENGTH);
  __builtin_memcpy(lpm_key_mac.data, mac, IPV6_BYTE_LENGTH);
  // bpf_printk("mac: %pI6", mac);
  key = MatchType_IpSet;
  if ((ret =
           bpf_map_update_elem(&lpm_key_map, &key, &lpm_key_daddr, BPF_ANY))) {
    return ret;
  };
  key = MatchType_SourceIpSet;
  if ((ret =
           bpf_map_update_elem(&lpm_key_map, &key, &lpm_key_saddr, BPF_ANY))) {
    return ret;
  };
  key = MatchType_Mac;
  if ((ret = bpf_map_update_elem(&lpm_key_map, &key, &lpm_key_mac, BPF_ANY))) {
    return ret;
  };

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
    if (!match_set) {
      return -EFAULT;
    }
    if (bad_rule || good_subrule) {
      key = match_set->type;
      // bpf_printk("key(match_set->type): %llu", key);
      // bpf_printk("Skip to judge. bad_rule: %d, good_subrule: %d", bad_rule,
      //            good_subrule);
      goto before_next_loop;
    }
    key = match_set->type;
    // bpf_printk("key(match_set->type): %llu", key);
    if ((lpm_key = bpf_map_lookup_elem(&lpm_key_map, &key))) {
      // bpf_printk(
      //     "CHECK: lpm_key_map, match_set->type: %u, not: %d, outbound: %u",
      //     match_set->type, match_set->not, match_set->outbound);
      // bpf_printk("\tip: %pI6", lpm_key->data);
      lpm = bpf_map_lookup_elem(&lpm_array_map, &match_set->index);
      if (unlikely(!lpm)) {
        return -EFAULT;
      }
      if (bpf_map_lookup_elem(lpm, lpm_key)) {
        // match_set hits.
        good_subrule = true;
      }
    } else if ((p_u16 = bpf_map_lookup_elem(&h_port_map, &key))) {
      // bpf_printk(
      //     "CHECK: h_port_map, match_set->type: %u, not: %d, outbound: %u",
      //     match_set->type, match_set->not, match_set->outbound);
      // bpf_printk("\tport: %u, range: [%u, %u]", *p_u16,
      //            match_set->port_range.port_start,
      //            match_set->port_range.port_end);
      if (*p_u16 >= match_set->port_range.port_start &&
          *p_u16 <= match_set->port_range.port_end) {
        good_subrule = true;
      }
    } else if ((p_u32 = bpf_map_lookup_elem(&l4proto_ipversion_map, &key))) {
      // bpf_printk("CHECK: l4proto_ipversion_map, match_set->type: %u, not:
      // %d,"
      //            "outbound: %u",
      //            match_set->type, match_set->not, match_set->outbound);
      if (*p_u32 & match_set->__value) {
        good_subrule = true;
      }
    } else if (match_set->type == MatchType_DomainSet) {
      // bpf_printk("CHECK: domain, match_set->type: %u, not: %d, "
      //            "outbound: %u",
      //            match_set->type, match_set->not, match_set->outbound);
      // Bottleneck of insns limit.
      // We fixed it by invoking bpf_map_lookup_elem here.

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
      if ((equal_ipv6_format(match_set->pname, _pname))) {
        good_subrule = true;
      }
    } else if (match_set->type == MatchType_Final) {
      // bpf_printk("CHECK: hit final");
      good_subrule = true;
    } else {
      // bpf_printk("CHECK: <unknown>, match_set->type: %u, not: %d, "
      //            "outbound: %u",
      //            match_set->type, match_set->not, match_set->outbound);
      return -EINVAL;
    }

  before_next_loop:
    // bpf_printk("good_subrule: %d, bad_rule: %d", good_subrule, bad_rule);
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
    // bpf_printk("_bad_rule: %d", bad_rule);
    if ((match_set->outbound & OUTBOUND_LOGICAL_MASK) !=
        OUTBOUND_LOGICAL_MASK) {
      // Tail of a rule (line).
      // Decide whether to hit.
      if (!bad_rule) {
        // bpf_printk("MATCHED: match_set->type: %u, match_set->not: %d",
        //            match_set->type, match_set->not );
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
}

// Do DNAT.
SEC("tc/ingress")
int tproxy_ingress(struct __sk_buff *skb) {
  struct ethhdr ethh;
  struct iphdr iph;
  struct ipv6hdr ipv6h;
  struct tcphdr tcph;
  struct udphdr udph;
  __sum16 bak_cksm = 0;
  __u8 ihl;
  __u8 ipversion;
  __u8 l4proto;
  bool tcp_state_syn;
  int ret = parse_transport(skb, &ethh, &iph, &ipv6h, &tcph, &udph, &ihl,
                            &ipversion, &l4proto);
  if (ret) {
    bpf_printk("parse_transport: %d", ret);
    return TC_ACT_OK;
  }

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

  // If this packet is sent to this host, accept it.
  __u32 tproxy_ip[4];
  int to_host = ip_is_host(ipversion, skb->ifindex, daddr, tproxy_ip);
  if (to_host < 0) { // error
    // bpf_printk("to_host: %ld", to_host);
    return TC_ACT_OK;
  }
  if (to_host == 1) {
    if (l4proto == IPPROTO_UDP && udph.dest == 53) {
      // To host:53. Process it.
    } else {
      // To host. Accept.
      return TC_ACT_OK;
    }
  }

  __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
  if (!tproxy_port) {
    return TC_ACT_OK;
  }

  if (l4proto == IPPROTO_TCP) {
    // Backup for further use.
    bak_cksm = tcph.check;
    tcp_state_syn = tcph.syn && !tcph.ack;
    struct ip_port key_src;
    __builtin_memset(&key_src, 0, sizeof(key_src));
    __builtin_memcpy(key_src.ip, saddr, IPV6_BYTE_LENGTH);
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

      // Print only new connection.
      // bpf_printk("tcp(lan): outbound: %u, %pI6:%u", outbound, daddr,
      //            bpf_ntohs(key_src.port));
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
    } else {
      // Rewrite to control plane.

      if (unlikely(tcp_state_syn)) {
        struct ip_port_outbound value_dst;
        __builtin_memset(&value_dst, 0, sizeof(value_dst));
        __builtin_memcpy(value_dst.ip, daddr, IPV6_BYTE_LENGTH);
        value_dst.port = tcph.dest;
        value_dst.outbound = outbound;
        bpf_map_update_elem(&tcp_dst_map, &key_src, &value_dst, BPF_ANY);
      }

      __u32 *dst_ip = daddr;
      __u16 dst_port = tcph.dest;
      if ((ret = rewrite_ip(skb, ipversion, IPPROTO_TCP, ihl, dst_ip, tproxy_ip,
                            true))) {
        bpf_printk("Shot IP: %d", ret);
        return TC_ACT_SHOT;
      }
      if ((ret = rewrite_port(skb, IPPROTO_TCP, ihl, dst_port, *tproxy_port,
                              true))) {
        bpf_printk("Shot Port: %d", ret);
        return TC_ACT_SHOT;
      }
    }
  } else if (l4proto == IPPROTO_UDP) {
    // Backup for further use.
    bak_cksm = udph.check;
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
    // bpf_printk("udp(lan): outbound: %u, %pI6:%u", new_hdr.outbound, daddr,
    //            bpf_ntohs(new_hdr.port));

    if (new_hdr.outbound == OUTBOUND_DIRECT) {
      return TC_ACT_OK;
    } else if (unlikely(new_hdr.outbound == OUTBOUND_BLOCK)) {
      return TC_ACT_SHOT;
    } else {
      // Rewrite to control plane.

      // Encap a header to transmit fullcone tuple.
      if ((ret = encap_after_udp_hdr(skb, ipversion, ihl, ipv4_tot_len,
                                     &new_hdr, sizeof(new_hdr)))) {
        return TC_ACT_SHOT;
      }

      // Rewrite udp dst ip.
      // bpf_printk("rewrite dst ip from %pI4", &ori_dst.ip);
      if ((ret = rewrite_ip(skb, ipversion, IPPROTO_UDP, ihl, new_hdr.ip,
                            tproxy_ip, true))) {
        bpf_printk("Shot IP: %d", ret);
        return TC_ACT_SHOT;
      }

      // Rewrite udp dst port.
      if ((ret = rewrite_port(skb, IPPROTO_UDP, ihl, new_hdr.port, *tproxy_port,
                              true))) {
        bpf_printk("Shot Port: %d", ret);
        return TC_ACT_SHOT;
      }
    }
  }

  // Print packet in hex for debugging (checksum or something else).
  // bpf_printk("DEBUG");
  // for (__u32 i = 0; i < skb->len && i < 200; i++) {
  //   __u8 t = 0;
  //   bpf_skb_load_bytes(skb, i, &t, 1);
  //   bpf_printk("%02x", t);
  // }
  __u8 *disable_l4_checksum =
      bpf_map_lookup_elem(&param_map, &disable_l4_rx_checksum_key);
  if (!disable_l4_checksum) {
    bpf_printk("Forgot to set disable_l4_checksum?");
    return TC_ACT_SHOT;
  }
  if (*disable_l4_checksum) {
    __u32 l4_cksm_off = l4_checksum_off(l4proto, ihl);
    // Restore the checksum or set it zero.
    if (*disable_l4_checksum == DisableL4ChecksumPolicy_SetZero) {
      bak_cksm = 0;
    }
    bpf_skb_store_bytes(skb, l4_cksm_off, &bak_cksm, sizeof(bak_cksm), 0);
  }
  return TC_ACT_OK;
}

/**
  FIXME: We can do packet modification as early as possible (for example, at
  lwt point) to avoid weird checksum offload problems by docker, etc. They do
  not obey the checksum specification. At present, we specially judge docker
  interfaces and disable checksum for them.

  References:
  https://github.com/torvalds/linux/blob/v6.1/samples/bpf/test_lwt_bpf.sh
  https://blog.csdn.net/Rong_Toa/article/details/109392163
*/
// Do SNAT.
SEC("tc/egress")
int tproxy_egress(struct __sk_buff *skb) {
  struct ethhdr ethh;
  struct iphdr iph;
  struct ipv6hdr ipv6h;
  struct tcphdr tcph;
  struct udphdr udph;
  __u8 ipversion;
  __u8 l4proto;
  __u8 ihl;
  int ret = parse_transport(skb, &ethh, &iph, &ipv6h, &tcph, &udph, &ihl,
                            &ipversion, &l4proto);
  if (ret) {
    return TC_ACT_OK;
  }

  // Parse saddr and daddr as ipv6 format.
  __be32 saddr[4];
  __be32 daddr[4];
  __be16 ipv4_tot_len = 0;
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
  if (l4proto == IPPROTO_TCP) {
    sport = tcph.source;
  } else if (l4proto == IPPROTO_UDP) {
    sport = udph.source;
  } else {
    return TC_ACT_OK;
  }

  // If not from tproxy, accept it.
  __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
  if (!tproxy_port || *tproxy_port != sport) {
    return TC_ACT_OK;
  }
  __be32 tproxy_ip[4];
  ret = ip_is_host(ipversion, skb->ifindex, saddr, tproxy_ip);
  if (!(ret == 1) || !equal_ipv6_format(saddr, tproxy_ip)) {
    return TC_ACT_OK;
  }

  __sum16 bak_cksm = 0;

  if (l4proto == IPPROTO_TCP) {

    // Lookup original dest.
    struct ip_port key_dst;
    __builtin_memset(&key_dst, 0, sizeof(key_dst));
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

    // Backup for further use.
    bak_cksm = tcph.check;

    __u32 *src_ip = saddr;
    __u16 src_port = tcph.source;
    if (rewrite_ip(skb, ipversion, IPPROTO_TCP, ihl, src_ip, original_dst->ip,
                   false) < 0) {
      bpf_printk("Shot IP: %d", ret);
      return TC_ACT_SHOT;
    }
    if (rewrite_port(skb, IPPROTO_TCP, ihl, src_port, original_dst->port,
                     false) < 0) {
      bpf_printk("Shot Port: %d", ret);
      return TC_ACT_SHOT;
    }
  } else if (l4proto == IPPROTO_UDP) {

    // Backup for further use.
    bak_cksm = udph.check;
    __u32 *src_ip = saddr;
    __u16 src_port = udph.source;
    /// NOTICE: Actually, we do not need symmetrical headers in client and
    /// server. We use it for convinience. This behavior may change in the
    /// future. Outbound here is useless and redundant.
    struct ip_port_outbound ori_src;
    __builtin_memset(&ori_src, 0, sizeof(ori_src));

    // Get source ip/port from our packet header.

    // Decap header to get fullcone tuple.
    decap_after_udp_hdr(skb, ipversion, ihl, ipv4_tot_len, &ori_src,
                        sizeof(ori_src));

    // Rewrite udp src ip
    if ((ret = rewrite_ip(skb, ipversion, IPPROTO_UDP, ihl, src_ip, ori_src.ip,
                          false))) {
      bpf_printk("Shot IP: %d", ret);
      return TC_ACT_SHOT;
    }

    // Rewrite udp src port
    if ((ret = rewrite_port(skb, IPPROTO_UDP, ihl, src_port, ori_src.port,
                            false))) {
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

  __u8 *disable_l4_checksum =
      bpf_map_lookup_elem(&param_map, &disable_l4_tx_checksum_key);
  if (!disable_l4_checksum) {
    bpf_printk("Forgot to set disable_l4_checksum?");
    return TC_ACT_SHOT;
  }
  if (*disable_l4_checksum) {
    __u32 l4_cksm_off = l4_checksum_off(l4proto, ihl);
    // Restore the checksum or set it zero.
    if (*disable_l4_checksum == DisableL4ChecksumPolicy_SetZero) {
      bak_cksm = 0;
    }
    bpf_skb_store_bytes(skb, l4_cksm_off, &bak_cksm, sizeof(bak_cksm), 0);
  }
  return TC_ACT_OK;
}

// This function will modify the content of src_key.
static __always_inline struct pid_pname *
lookup_src_pid_map(__u8 ipversion, struct ip_port_proto *src_key) {
  // Lookup twice or third. First for unspecific address, second for interface
  // address.

  // Lookup pid in src_pid_map.
  struct pid_pname *pid_pname;
  if ((pid_pname = bpf_map_lookup_elem(&src_pid_map, src_key))) {
    return pid_pname;
  }

  // Second look-up.
  // Set to unspecific address.
  if (ipversion == 6) {
    __builtin_memset(src_key, 0, sizeof(struct ip_port_proto));
  } else {
    src_key->ip[3] = 0;
  }
  if ((pid_pname = bpf_map_lookup_elem(&src_pid_map, src_key))) {
    return pid_pname;
  }
  if (ipversion == 6) {
    return NULL;
  }

  // Third look-up for IPv4 packet.
  // Lookup IPv6 unspecific address.
  // https://github.com/torvalds/linux/blob/62fb9874f5da54fdb243003b386128037319b219/net/ipv4/af_inet.c#L475
  src_key->ip[2] = 0;
  return bpf_map_lookup_elem(&src_pid_map, src_key);
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

    // Redirect.
    if ((ret = bpf_redirect(skb->ifindex, BPF_F_INGRESS)) == TC_ACT_SHOT) {
      bpf_printk("Shot bpf_redirect: %d", ret);
      return TC_ACT_SHOT;
    }
    return TC_ACT_REDIRECT;
  } else {
    // Normal packets.

    // Prepare key.
    struct ip_port_proto src_key;
    __builtin_memset(&src_key, 0, sizeof(struct ip_port_proto));
    src_key.proto = l4proto;
    __builtin_memcpy(src_key.ip, saddr, IPV6_BYTE_LENGTH);
    src_key.port = sport;

    struct pid_pname *pid_pname = lookup_src_pid_map(ipversion, &src_key);
    if (pid_pname) {
      // Get tproxy pid and compare if they are equal.
      __u32 *pid_tproxy;
      if (!(pid_tproxy =
                bpf_map_lookup_elem(&param_map, &control_plane_pid_key))) {
        bpf_printk("control_plane_pid is not set.");
        return TC_ACT_SHOT;
      }
      if (pid_pname->pid == *pid_tproxy) {
        // Control plane to direct.
        // bpf_printk("Control plane to direct.");
        return TC_ACT_OK;
      }
    } else {
      if ((skb->mark & 0x80) == 0x80) {
        bpf_printk("No pid_pname found. But it should not happen: %pI6:%u (%u)",
                   saddr, bpf_ntohs(sport), l4proto);
      }
    }

    // Not from tproxy; from other processes.

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

        // Print only new connection.
        // bpf_printk("tcp(wan): outbound: %u, %pI6:%u", outbound, daddr,
        //            bpf_ntohs(key_src.port));
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
      } else {
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
        if ((ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
                                       ethh.h_source, sizeof(ethh.h_source),
                                       0))) {
          return TC_ACT_SHOT;
        }
        if ((ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
                                       special_mac_to_tproxy,
                                       sizeof(ethh.h_source), 0))) {
          return TC_ACT_SHOT;
        };

        // Redirect.
        if ((ret = bpf_redirect(skb->ifindex, BPF_F_INGRESS)) == TC_ACT_SHOT) {
          bpf_printk("Shot bpf_redirect: %d", ret);
          return TC_ACT_SHOT;
        }
        return TC_ACT_REDIRECT;
      }
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
      // bpf_printk("udp(wan): outbound: %u, %pI6:%u", new_hdr.outbound, daddr,
      //            bpf_ntohs(new_hdr.port));

      if (new_hdr.outbound == OUTBOUND_DIRECT) {
        return TC_ACT_OK;
      } else if (unlikely(new_hdr.outbound == OUTBOUND_BLOCK)) {
        return TC_ACT_SHOT;
      } else {
        // Rewrite to control plane.

        // Write mac.
        if ((ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
                                       ethh.h_source, sizeof(ethh.h_source),
                                       0))) {
          return TC_ACT_SHOT;
        }
        if ((ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
                                       special_mac_to_tproxy,
                                       sizeof(ethh.h_source), 0))) {
          return TC_ACT_SHOT;
        };

        // Encap a header to transmit fullcone tuple.
        if ((ret = encap_after_udp_hdr(skb, ipversion, ihl, ipv4_tot_len,
                                       &new_hdr, sizeof(new_hdr)))) {
          return TC_ACT_SHOT;
        }

        // Redirect from egress to ingress.
        if ((ret = bpf_redirect(skb->ifindex, BPF_F_INGRESS)) == TC_ACT_SHOT) {
          bpf_printk("Shot bpf_redirect: %d", ret);
          return TC_ACT_SHOT;
        }
        return TC_ACT_REDIRECT;
      }
    }
  }

  return TC_ACT_OK;
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

  if (tproxy_response) {
    // Send the tproxy response packet to origin.

    // If a client sent a packet at the begining, let's say the client is
    // sender and its ip is right host ip.
    // saddr is host ip and right sender ip.
    // dport is sender sport. See (1).
    // bpf_printk("[%u]should send to origin: %pI6:%u", l4proto, saddr,
    //            bpf_ntohs(dport));

    if (l4proto == IPPROTO_TCP) {
      // Lookup original dest as sip and sport.
      struct ip_port key_dst;
      __builtin_memset(&key_dst, 0, sizeof(key_dst));
      // Use daddr as key in WAN because tproxy (control plane) also lookups the
      // map element using income client ip (that is daddr).
      __builtin_memcpy(key_dst.ip, daddr, sizeof(key_dst.ip));
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
      if (rewrite_ip(skb, ipversion, IPPROTO_TCP, ihl, saddr, original_dst->ip,
                     false) < 0) {
        bpf_printk("Shot IP: %d", ret);
        return TC_ACT_SHOT;
      }
      if (rewrite_port(skb, IPPROTO_TCP, ihl, sport, original_dst->port,
                       false) < 0) {
        bpf_printk("Shot Port: %d", ret);
        return TC_ACT_SHOT;
      }
    } else if (l4proto == IPPROTO_UDP) {

      /// NOTICE: Actually, we do not need symmetrical headers in client and
      /// server. We use it for convinience. This behavior may change in the
      /// future. Outbound here is useless and redundant.
      struct ip_port_outbound ori_src;
      __builtin_memset(&ori_src, 0, sizeof(ori_src));

      // Get source ip/port from our packet header.

      // Decap header to get fullcone tuple.
      decap_after_udp_hdr(skb, ipversion, ihl, ipv4_tot_len, &ori_src,
                          sizeof(ori_src));

      // Rewrite udp src ip
      if ((ret = rewrite_ip(skb, ipversion, IPPROTO_UDP, ihl, saddr, ori_src.ip,
                            false))) {
        bpf_printk("Shot IP: %d", ret);
        return TC_ACT_SHOT;
      }

      // Rewrite udp src port
      if ((ret = rewrite_port(skb, IPPROTO_UDP, ihl, sport, ori_src.port,
                              false))) {
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
    // Rewrite dip.
    if (rewrite_ip(skb, ipversion, l4proto, ihl, daddr, saddr, true) < 0) {
      bpf_printk("Shot IP: %d", ret);
      return TC_ACT_SHOT;
    }
  } else {
    // Should send the packet to tproxy.

    // Get tproxy ip and port.
    __be32 tproxy_ip[4];
    // saddr should be tproxy ip.
    __builtin_memcpy(tproxy_ip, saddr, sizeof(tproxy_ip));
    __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
    if (!tproxy_port) {
      return TC_ACT_OK;
    }
    // bpf_printk("should send to: %pI6:%u", tproxy_ip,
    // bpf_ntohs(*tproxy_port));

    if ((ret = rewrite_ip(skb, ipversion, l4proto, ihl, daddr, tproxy_ip,
                          true))) {
      bpf_printk("Shot IP: %d", ret);
      return TC_ACT_SHOT;
    }
    // (1) Use daddr as saddr to pass NIC verification. Notice that we do not
    // modify the <sport> so tproxy will send packet to it.
    if ((ret = rewrite_ip(skb, ipversion, l4proto, ihl, saddr, daddr, false))) {
      bpf_printk("Shot IP: %d", ret);
      return TC_ACT_SHOT;
    }

    // Rewrite udp dst port.
    if ((ret = rewrite_port(skb, l4proto, ihl, dport, *tproxy_port, true))) {
      bpf_printk("Shot Port: %d", ret);
      return TC_ACT_SHOT;
    }
  }

  __u32 l4_cksm_off = l4_checksum_off(l4proto, ihl);
  // Restore the checksum or set it zero.
  __sum16 bak_cksm = 0;
  bpf_skb_store_bytes(skb, l4_cksm_off, &bak_cksm, sizeof(bak_cksm), 0);
  return TC_ACT_OK;
}

static int __always_inline build_key_by_sk(struct sock *sk,
                                           struct ip_port_proto *src_key) {

  // Build key.
  __builtin_memset(src_key, 0, sizeof(struct ip_port_proto));

  __u16 sk_type = BPF_CORE_READ(sk, sk_type);
  if (sk_type == SOCK_STREAM) {
    src_key->proto = IPPROTO_TCP;
    // bpf_printk("TCP bind");
  } else if (sk_type == SOCK_DGRAM) {
    src_key->proto = IPPROTO_UDP;
    // bpf_printk("UDP bind");
  } else if (sk_type == SOCK_RAW) {
    __u16 sk_proto = BPF_CORE_READ(sk, sk_protocol);
    if (sk_proto == IPPROTO_TCP) {
      src_key->proto = IPPROTO_TCP;
      // bpf_printk("RAW TCP bind");
    } else if (sk_proto == IPPROTO_TCP) {
      src_key->proto = IPPROTO_UDP;
      // bpf_printk("RAW UDP bind");
    } else {
      return -ERANGE;
    }
  } else {
    return -ERANGE;
  }
  struct inet_sock *inet = (struct inet_sock *)sk;
  unsigned short family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family == AF_INET) {
    src_key->ip[2] = bpf_htonl(0x0000ffff);
    src_key->ip[3] = BPF_CORE_READ(inet, inet_saddr);
  } else if (family == AF_INET6) {
    BPF_CORE_READ_INTO(&src_key->ip, inet, pinet6, saddr.in6_u.u6_addr32);
  } else {
    if (family == AF_UNSPEC) {
      bpf_printk("oh shit AF_UNSPEC");
    }
    return -ERANGE;
  }
  src_key->port = BPF_CORE_READ(inet, inet_sport);
  return 0;
}

static int __always_inline update_map_elem_by_sk(struct sock *sk) {
  int ret;

  // Build key.
  struct ip_port_proto src_key;
  if ((ret = build_key_by_sk(sk, &src_key))) {
    return ret;
  }

  // Build value.
  struct pid_pname val;
  __builtin_memset(&val, 0, sizeof(struct pid_pname));
  val.pid = bpf_get_current_pid_tgid() >> 32;
  //  struct task_struct *t = (void *)bpf_get_current_task();
  if ((ret = bpf_get_current_comm(val.pname, sizeof(val.pname)))) {
    return ret;
  }

  // Update map.
  /// TODO: We can use BPF_NOEXIST here to improve the performance.
  ///   But will the socket be released after processes dead abnormally?
  if ((ret = bpf_map_update_elem(&src_pid_map, &src_key, &val, BPF_ANY))) {
    // bpf_printk("setup_mapping_from_sk: failed update map: %d", ret);
    return ret;
  }

  // bpf_printk("setup_mapping_from_sk: %pI6:%u (%d)", src_key.ip,
  //            bpf_ntohs(src_key.port), src_key.proto);
  // bpf_printk("setup_mapping_from_sk: -> %s (%d)", val.pname, val.pid);
  return 0;
}

// Get sip, sport to pid, pname mapping.
// kernel 5.5+
// IPv4/IPv6 TCP/UDP send.
SEC("fexit/inet_release")
int BPF_PROG(inet_release, struct sock *sk, int ret) {
  if (unlikely(ret)) {
    return 0;
  }
  // Build key.
  struct ip_port_proto src_key;
  if ((ret = build_key_by_sk(sk, &src_key))) {
    return 0;
  }
  if ((ret = bpf_map_delete_elem(&src_pid_map, &src_key))) {
    // bpf_printk("setup_mapping_from_sk: failed update map: %d", ret);
    return 0;
  }
  return 0;
}

// Get sip, sport to pid, pname mapping.
// kernel 5.5+
// IPv4/IPv6 TCP/UDP send.
SEC("fexit/inet_send_prepare")
int BPF_PROG(inet_send_prepare, struct sock *sk, int ret) {
  if (unlikely(ret)) {
    return 0;
  }
  /// TODO: inet_release
  update_map_elem_by_sk(sk);
  return 0;
}

// Get sip, sport to pid, pname mapping.
// kernel 5.5+
// IPv4 TCP/UDP listen.
SEC("fexit/inet_bind")
int BPF_PROG(inet_bind, struct socket *sock, struct sockaddr *uaddr,
             int addr_len, int ret) {
  if (ret) {
    return 0;
  }
  /// TODO: inet_release
  update_map_elem_by_sk(sock->sk);
  return 0;
}

// Get sip, sport to pid, pname mapping.
// kernel 5.5+
// IPv4 TCP connect.
// We use fentry because it "Build a SYN and send it off".
// https://github.com/torvalds/linux/blob/62fb9874f5da54fdb243003b386128037319b219/net/ipv4/tcp_output.c#L3820
SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk) {
  /// TODO: inet4_release
  update_map_elem_by_sk(sk);
  return 0;
}

// Get sip, sport to pid, pname mapping.
// kernel 5.5+
// IPv4 UDP sendto/sendmsg.
SEC("fexit/inet_autobind")
int BPF_PROG(inet_autobind, struct sock *sk, int ret) {
  if (ret) {
    return 0;
  }
  /// TODO: inet4_release
  update_map_elem_by_sk(sk);
  return 0;
}

// Get sip, sport to pid, pname mapping.
// kernel 5.5+
// IPv6 TCP/UDP listen.
SEC("fexit/inet6_bind")
int BPF_PROG(inet6_bind, struct socket *sock, struct sockaddr *uaddr,
             int addr_len, int ret) {
  if (ret) {
    return 0;
  }
  /// TODO: inet6_release
  update_map_elem_by_sk(sock->sk);
  return 0;
}
SEC("license") const char __license[] = "Dual BSD/GPL";