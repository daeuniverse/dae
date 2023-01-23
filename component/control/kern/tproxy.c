/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

#include <asm-generic/errno-base.h>
#include <iproute2/bpf_elf.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <net/if.h>
#include <stdbool.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <sys/cdefs.h>
#include <sys/types.h>

// #include "addr.h"

// #define likely(x) x
// #define unlikely(x) x
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

#define IPV6_BYTE_LENGTH 16

#define IPV4_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IPV4_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IPV4_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IPV6_DST_OFF (ETH_HLEN + offsetof(struct ipv6hdr, daddr))
#define IPV6_SRC_OFF (ETH_HLEN + offsetof(struct ipv6hdr, saddr))

#define MAX_PARAM_LEN 16
#define MAX_INTERFACE_NUM 128
#define MAX_ROUTING_LEN 96
#define MAX_LPM_SIZE 20480
#define MAX_LPM_NUM (MAX_ROUTING_LEN + 8)
#define IPV6_MAX_EXTENSIONS 4

#define OUTBOUND_DIRECT 0
#define OUTBOUND_CONTROL_PLANE_ROUTE 0xFE
#define OUTBOUND_LOGICAL_AND 0xFF

enum {
  DISABLE_L4_CHECKSUM_POLICY_ENABLE_L4_CHECKSUM,
  DISABLE_L4_CHECKSUM_POLICY_RESTORE,
  DISABLE_L4_CHECKSUM_POLICY_SET_ZERO,
};
#define OUTBOUND_LOGICAL_AND 0xFF

// Param keys:
static const __u32 ips_len_key __attribute__((unused, deprecated)) = 0;
static const __u32 tproxy_port_key = 1;
static const __u32 disable_l4_tx_checksum_key = 2;
static const __u32 disable_l4_rx_checksum_key = 3;
static const __u32 epoch_key __attribute__((unused, deprecated)) = 4;
static const __u32 routings_len_key __attribute__((unused, deprecated)) = 5;

static __be32 unspecific_ipv6[4] __attribute__((__unused__)) = {0, 0, 0, 0};

struct ip_port {
  __be32 ip[4];
  __be16 port;
};

struct ip_port_proto {
  __be32 ip[4];
  __be16 port;
  __u8 proto;
};

struct ip_port_outbound {
  __be32 ip[4];
  __be16 port;
  __u8 outbound;
  __u8 unused;
};

/// TODO: 4-Way-Handshake can be initiated by any party,
/// and remove them from the dst_map by conntrack.
// Dest map:
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key,
         struct ip_port_proto); // As TCP client side [SYN, !ACK],
                                // (source ip, source port, tcp) is
                                // enough for identifier. And UDP client
                                // side does not care it (full-cone).
  __type(value, struct ip_port_outbound); // Original target.
  __uint(max_entries, 0xFF << 2);
  /// NOTICE: It MUST be pinned.
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} dst_map SEC(".maps");

// Params:
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_PARAM_LEN);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} param_map SEC(".maps");

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
} ifindex_ip_map SEC(".maps");

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
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __array(values, struct map_lpm_type);
} lpm_array_map SEC(".maps");

// Array of routing:
enum __attribute__((__packed__)) ROUTING_TYPE {
  /// WARNING: MUST SYNC WITH common/consts/ebpf.go.
  ROUTING_TYPE_DOMAIN_SET,
  ROUTING_TYPE_IP_SET,
  ROUTING_TYPE_SOURCE_IP_SET,
  ROUTING_TYPE_PORT,
  ROUTING_TYPE_SOURCE_PORT,
  ROUTING_TYPE_NETWORK,
  ROUTING_TYPE_IPVERSION,
  ROUTING_TYPE_MAC,
  ROUTING_TYPE_FINAL,
};
enum __attribute__((__packed__)) NETWORK_TYPE {
  NETWORK_TYPE_TCP = 1,
  NETWORK_TYPE_UDP = 2,
  NETWORK_TYPE_TCP_UDP = 3,
};
enum __attribute__((__packed__)) IP_VERSION {
  IPVERSION_4 = 1,
  IPVERSION_6 = 2,
  IPVERSION_X = 3,
};
struct port_range {
  __u16 port_start;
  __u16 port_end;
};
struct routing {
  union {
    __u32 __value; // Placeholder for bpf2go.

    __u32 index;
    struct port_range port_range;
    enum NETWORK_TYPE network_type;
    enum IP_VERSION ip_version;
  };
  enum ROUTING_TYPE type;
  __u8 outbound; // 255 means logical AND. 254 means dirty. User-defined value
                 // range is [0, 253].
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct routing);
  __uint(max_entries, MAX_ROUTING_LEN);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} routing_map SEC(".maps");

struct domain_routing {
  __u32 bitmap[MAX_ROUTING_LEN / 32];
  /// DEPRECATED: Epoch is the epoch at the write time. Every time the control
  /// plane restarts, epoch += 1. It was deprecated because long connection will
  /// keep their states by persistent dst_map (we only need to know if it is a
  /// old connection).
  __u32 epoch;
};
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __be32[4]);
  __type(value, struct domain_routing);
  __uint(max_entries, 65535);
  // __uint(pinning, LIBBPF_PIN_BY_NAME);
} domain_routing_map SEC(".maps");

// Functions:

static __always_inline bool equal_ipv6(__be32 x[4], __be32 y[4]) {
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

static __always_inline long rewrite_ip(struct __sk_buff *skb, bool is_ipv6,
                                       __u8 proto, __u8 ihl, __be32 old_ip[4],
                                       __be32 new_ip[4], bool is_dest) {
  // Nothing to do.
  if (equal_ipv6(old_ip, new_ip)) {
    return 0;
  }
  // bpf_printk("%pI6->%pI6", old_ip, new_ip);

  __u32 l4_cksm_off = l4_checksum_off(proto, ihl);
  long ret;
  // BPF_F_PSEUDO_HDR indicates the part we want to modify is part of the
  // pseudo header.
  __u32 l4flags = BPF_F_PSEUDO_HDR;
  if (proto == IPPROTO_UDP) {
    l4flags |= BPF_F_MARK_MANGLED_0;
  }

  if (!is_ipv6) {
    __be32 _old_ip = old_ip[3];
    __be32 _new_ip = new_ip[3];

    if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, _old_ip, _new_ip,
                                   l4flags | sizeof(_new_ip)))) {
      bpf_printk("bpf_l4_csum_replace: %ld", ret);
      return ret;
    }

    if ((ret = bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, _old_ip, _new_ip,
                                   sizeof(_new_ip)))) {
      return ret;
    }
    bpf_printk("%pI4 -> %pI4", &_old_ip, &_new_ip);

    ret = bpf_skb_store_bytes(skb, is_dest ? IPV4_DST_OFF : IPV4_SRC_OFF,
                              &_new_ip, sizeof(_new_ip), 0);
    if (ret) {
      bpf_printk("bpf_skb_store_bytes: %ld", ret);
      return ret;
    }
  } else {
    __s64 cksm =
        bpf_csum_diff(new_ip, IPV6_BYTE_LENGTH, old_ip, IPV6_BYTE_LENGTH, 0);
    if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, 0, cksm, l4flags))) {
      bpf_printk("bpf_l4_csum_replace: %ld", ret);
      return ret;
    }
    bpf_printk("%pI6 -> %pI6", old_ip, new_ip);

    ret = bpf_skb_store_bytes(skb, is_dest ? IPV6_DST_OFF : IPV6_SRC_OFF,
                              new_ip, IPV6_BYTE_LENGTH, 0);
    if (ret) {
      bpf_printk("bpf_skb_store_bytes: %ld", ret);
      return ret;
    }
  }

  return 0;
}

static __always_inline long rewrite_port(struct __sk_buff *skb, __u8 proto,
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

  long ret;
  if ((ret = bpf_l4_csum_replace(skb, cksm_off, old_port, new_port,
                                 l4flags | sizeof(new_port)))) {
    bpf_printk("bpf_l4_csum_replace: %ld", ret);
    return ret;
  }
  ret = bpf_skb_store_bytes(skb, port_off, &new_port, sizeof(new_port), 0);

  if (ret) {
    return ret;
  }

  return 0;
}

static __always_inline long
handle_ipv6_extensions(void *data, void *data_end, __u8 hdr,
                       struct tcphdr **tcph, struct udphdr **udph, __u8 *ihl) {
  __u8 hdr_length = 0;
  __u8 nexthdr;
  *ihl = sizeof(struct ipv6hdr) / 4;
  // We only process TCP and UDP traffic.

  // #pragma unroll
  for (int i = 0; i < IPV6_MAX_EXTENSIONS; i++,
           data = (__u8 *)data + hdr_length, hdr = nexthdr,
           *ihl += hdr_length / 4) {
    if (hdr_length % 4) {
      bpf_printk("IPv6 extension length is not multiples of 4");
      return 1;
    }
    switch (hdr) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_FRAGMENT:
      if (hdr == IPPROTO_FRAGMENT) {
        hdr_length = 4;
      } else {
        if ((void *)((__u8 *)data + 2) > data_end) {
          bpf_printk("not a valid IPv6 packet");
          return -EFAULT;
        }
        hdr_length = *((__u8 *)data + 1);
      }
      if ((void *)((__u8 *)data + hdr_length) > data_end) {
        bpf_printk("not a valid IPv6 packet");
        return -EFAULT;
      }
      nexthdr = *(__u8 *)data;
      break;
    case IPPROTO_TCP:
      // Upper layer;
      // Skip ipv4hdr and options to get tcphdr.
      *tcph = (struct tcphdr *)data;
      // Should be complete tcphdr.
      if ((void *)(*tcph + 1) > data_end) {
        bpf_printk("not a valid TCP packet");
        return -EFAULT;
      }
      return 0;
    case IPPROTO_UDP:
      // Upper layer;
      // Skip ipv4hdr and options to get tcphdr.
      *udph = (struct udphdr *)data;
      // Should be complete udphdr.
      if ((void *)(*udph + 1) > data_end) {
        bpf_printk("not a valid UDP packet");
        return -EFAULT;
      }
      return 0;
    case IPPROTO_ICMPV6:
      // Upper layer;
    case IPPROTO_NONE:
      // No more extension.
      return 1;
    default:
      // Unsupported ipv6 extention header;
      bpf_printk("unsupported protocol: %u", hdr);
      return 1;
    }
  }
  bpf_printk("exceeds IPV6_MAX_EXTENSIONS limit");
  return 1;
}

static __always_inline long
parse_transport(struct __sk_buff *skb, struct ethhdr **ethh, struct iphdr **iph,
                struct ipv6hdr **ipv6h, struct tcphdr **tcph,
                struct udphdr **udph, __u8 *ihl) {

  void *data_end = (void *)(unsigned long)skb->data_end;
  void *data = (void *)(unsigned long)skb->data;
  struct ethhdr *eth = data;

  if (unlikely((void *)(eth + 1) > data_end)) {
    bpf_printk("not ethernet packet");
    return 1;
  }

  *ethh = eth;
  *iph = NULL;
  *ipv6h = NULL;
  *tcph = NULL;
  *udph = NULL;
  // bpf_printk("parse_transport: h_proto: %u ? %u %u", eth->h_proto,
  //            bpf_htons(ETH_P_IP), bpf_htons(ETH_P_IPV6));
  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    // eth + 1: skip eth hdr.
    *iph = (struct iphdr *)(eth + 1);
    if (unlikely((void *)(*iph + 1) > data_end)) {
      return -EFAULT;
    }
    // We only process TCP and UDP traffic.
    if (likely((*iph)->protocol == IPPROTO_TCP)) {
      // Skip ipv4hdr and options to get tcphdr.
      *tcph = (struct tcphdr *)((__u32 *)(*iph) + (*iph)->ihl);
      // Should be complete tcphdr.
      if ((void *)(*tcph + 1) > data_end) {
        bpf_printk("not a valid TCP packet");
        return -EFAULT;
      }
    } else if (likely((*iph)->protocol == IPPROTO_UDP)) {
      // Skip ipv4hdr and options to get tcphdr.
      *udph = (struct udphdr *)((__u32 *)(*iph) + (*iph)->ihl);
      // Should be complete udphdr.
      if ((void *)(*udph + 1) > data_end) {
        bpf_printk("not a valid UDP packet");
        return -EFAULT;
      }
    } else {
      bpf_printk("IP but not TCP/UDP packet: protocol is %u", (*iph)->protocol);
      return 1;
    }
    *ihl = (*iph)->ihl;
    return 0;
  } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    // eth + 1: skip eth hdr.
    *ipv6h = (struct ipv6hdr *)(eth + 1);
    if (unlikely((void *)(*ipv6h + 1) > data_end)) {
      bpf_printk("not a valid IPv6 packet");
      return -EFAULT;
    }
    return handle_ipv6_extensions((void *)(*ipv6h + 1), data_end,
                                  (*ipv6h)->nexthdr, tcph, udph, ihl);
  }
  return 1;
}

static __always_inline long ip_is_host(bool is_ipv6, __u32 ifindex,
                                       __be32 ip[4],
                                       __be32 (*first_interface_ip)[4]) {
  struct if_ip *if_ip = bpf_map_lookup_elem(&ifindex_ip_map, &ifindex);
  if (unlikely(!if_ip)) {
    return -1;
  }
  __u32 host_ip[4];
  if (!is_ipv6 && (*if_ip).hasIp4) {
    __builtin_memcpy(host_ip, (*if_ip).ip4, IPV6_BYTE_LENGTH);
  } else if (is_ipv6 && (*if_ip).hasIp6) {
    __builtin_memcpy(host_ip, (*if_ip).ip6, IPV6_BYTE_LENGTH);
  } else {
    // Should TC_ACT_OK outer.
    return -EFAULT;
  }
  if (first_interface_ip) {
    __builtin_memcpy(*first_interface_ip, host_ip, IPV6_BYTE_LENGTH);
  }
  if (equal_ipv6(ip, host_ip)) {
    return 1;
  }
  return 0;
}

static __always_inline long adjust_udp_len(struct __sk_buff *skb, __u16 oldlen,
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
  long ret;

  __u32 udp_csum_off = l4_checksum_off(IPPROTO_UDP, ihl);
  // replace twice because len exists both pseudo hdr and hdr.
  if ((ret = bpf_l4_csum_replace(
           skb, udp_csum_off, oldlen, newlen,
           sizeof(oldlen) | BPF_F_PSEUDO_HDR | // udp len is in the pseudo hdr
               BPF_F_MARK_MANGLED_0))) {
    bpf_printk("bpf_l4_csum_replace newudplen: %ld", ret);
    return ret;
  }
  if ((ret = bpf_l4_csum_replace(skb, udp_csum_off, oldlen, newlen,
                                 sizeof(oldlen) | BPF_F_MARK_MANGLED_0))) {
    bpf_printk("bpf_l4_csum_replace newudplen: %ld", ret);
    return ret;
  }
  if ((ret = bpf_skb_store_bytes(
           skb, (__u32)ETH_HLEN + ihl * 4 + offsetof(struct udphdr, len),
           &newlen, sizeof(oldlen), 0))) {
    bpf_printk("bpf_skb_store_bytes newudplen: %ld", ret);
    return ret;
  }
  return 0;
}

static __always_inline long adjust_ipv4_len(struct __sk_buff *skb, __u16 oldlen,
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
  long ret;
  if ((ret = bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, oldlen, newlen,
                                 sizeof(oldlen)))) {
    bpf_printk("bpf_l3_csum_replace newudplen: %ld", ret);
    return ret;
  }
  if ((ret = bpf_skb_store_bytes(
           skb, (__u32)ETH_HLEN + offsetof(struct iphdr, tot_len), &newlen,
           sizeof(oldlen), 0))) {
    bpf_printk("bpf_skb_store_bytes newiplen: %ld", ret);
    return ret;
  }
  return 0;
}

static __always_inline long encap_after_udp_hdr(struct __sk_buff *skb,
                                                bool is_ipv6, __u8 ihl,
                                                __be16 iphdr_tot_len,
                                                void *newhdr, __u32 newhdrlen) {
  if (unlikely(newhdrlen % 4 != 0)) {
    bpf_trace_printk("encap_after_udp_hdr: unexpected newhdrlen value %u :must "
                     "be a multiple of 4",
                     newhdrlen);
    return -EINVAL;
  }

  long ret = 0;
  long ip_off = ETH_HLEN;
  // Calculate offsets using add instead of subtract to avoid verifier problems.
  long ipp_len = ihl * 4;
  long udp_payload_off = ip_off + ipp_len + sizeof(struct udphdr);

  // Backup for further use.
  struct udphdr reserved_udphdr;
  __builtin_memset(&reserved_udphdr, 0, sizeof(reserved_udphdr));
  if ((ret = bpf_skb_load_bytes(skb, ip_off + ipp_len, &reserved_udphdr,
                                sizeof(reserved_udphdr)))) {
    bpf_printk("bpf_skb_load_bytes: %ld", ret);
    return ret;
  }
  // Add room for new udp payload header.
  if ((ret = bpf_skb_adjust_room(skb, newhdrlen, BPF_ADJ_ROOM_NET,
                                 BPF_F_ADJ_ROOM_NO_CSUM_RESET))) {
    bpf_printk("UDP ADJUST ROOM: %ld", ret);
    return ret;
  }
  // Move the new room to the front of the UDP payload.
  if ((ret = bpf_skb_store_bytes(skb, ip_off + ipp_len, &reserved_udphdr,
                                 sizeof(reserved_udphdr), 0))) {
    bpf_printk("bpf_skb_store_bytes reserved_udphdr: %ld", ret);
    return ret;
  }

  // Rewrite ip len.
  if (!is_ipv6) {
    if ((ret = adjust_ipv4_len(skb, iphdr_tot_len, newhdrlen))) {
      bpf_printk("adjust_ip_len: %ld", ret);
      return ret;
    }
  }

  // Rewrite udp len.
  if ((ret = adjust_udp_len(skb, reserved_udphdr.len, ihl, newhdrlen))) {
    bpf_printk("adjust_udp_len: %ld", ret);
    return ret;
  }

  // Rewrite udp payload.
  __u32 l4_cksm_off = l4_checksum_off(IPPROTO_UDP, ihl);
  __s64 cksm = bpf_csum_diff(NULL, 0, newhdr, newhdrlen, 0);
  if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, 0, cksm,
                                 BPF_F_MARK_MANGLED_0))) {
    bpf_printk("bpf_l4_csum_replace 2: %ld", ret);
    return ret;
  }
  if ((ret = bpf_skb_store_bytes(skb, udp_payload_off, newhdr, newhdrlen, 0))) {
    bpf_printk("bpf_skb_store_bytes 2: %ld", ret);
    return ret;
  }
  return 0;
}

static __always_inline int decap_after_udp_hdr(struct __sk_buff *skb,
                                               bool is_ipv6, __u8 ihl,
                                               __be16 iphdr_tot_len, void *to,
                                               __u32 decap_hdrlen) {
  if (unlikely(decap_hdrlen % 4 != 0)) {
    bpf_trace_printk(
        "encap_after_udp_hdr: unexpected decap_hdrlen value %u :must "
        "be a multiple of 4",
        decap_hdrlen);
    return -EINVAL;
  }
  long ret = 0;
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
    bpf_printk("bpf_skb_load_bytes: %ld", ret);
    return ret;
  }

  // Load the hdr to decap.
  if ((ret = bpf_skb_load_bytes(skb, ip_off + ipp_len + sizeof(struct udphdr),
                                to, decap_hdrlen))) {
    bpf_printk("bpf_skb_load_bytes decap_hdr: %ld", ret);
    return ret;
  }

  // Move the udphdr to the front of the real UDP payload.
  if ((ret =
           bpf_skb_store_bytes(skb, ip_off + ipp_len + decap_hdrlen,
                               &reserved_udphdr, sizeof(reserved_udphdr), 0))) {
    bpf_printk("bpf_skb_store_bytes reserved_udphdr: %ld", ret);
    return ret;
  }

  // Adjust room to decap the header.
  if ((ret = bpf_skb_adjust_room(skb, -decap_hdrlen, BPF_ADJ_ROOM_NET,
                                 BPF_F_ADJ_ROOM_NO_CSUM_RESET))) {
    bpf_printk("UDP ADJUST ROOM: %ld", ret);
    return ret;
  }

  // Rewrite ip len.
  if (!is_ipv6) {
    if ((ret = adjust_ipv4_len(skb, iphdr_tot_len, -decap_hdrlen))) {
      bpf_printk("adjust_ip_len: %ld", ret);
      return ret;
    }
  }

  // Rewrite udp len.
  if ((ret = adjust_udp_len(skb, reserved_udphdr.len, ihl, -decap_hdrlen))) {
    bpf_printk("adjust_udp_len: %ld", ret);
    return ret;
  }

  // Rewrite udp checksum.
  __u32 udp_csum_off = l4_checksum_off(IPPROTO_UDP, ihl);
  __s64 cksm = bpf_csum_diff(to, decap_hdrlen, 0, 0, 0);
  if ((ret = bpf_l4_csum_replace(skb, udp_csum_off, 0, cksm,
                                 BPF_F_MARK_MANGLED_0))) {
    bpf_printk("bpf_l4_csum_replace 2: %ld", ret);
    return ret;
  }
  return 0;
}

// Do not use __always_inline here because this function is too heavy.
static long routing(__u8 flag[2], void *l4_hdr, __be32 saddr[4],
                    __be32 daddr[4], __be32 mac[4]) {
#define _network flag[0]
#define _ipversion flag[1]
  // // Get len of routings and epoch from param_map.
  // __u32 *routings_len = bpf_map_lookup_elem(&param_map, &routings_len_key);
  // if (!routings_len) {
  //   return -EINVAL;
  // }
  // __u32 *epoch = bpf_map_lookup_elem(&param_map, &epoch_key);
  // if (!epoch) {
  //   return -EINVAL;
  // }
  // Define variables for further use.
  __u16 h_dport;
  __u16 h_sport;
  if (_network == NETWORK_TYPE_TCP) {
    h_dport = bpf_ntohs(((struct tcphdr *)l4_hdr)->dest);
    h_sport = bpf_ntohs(((struct tcphdr *)l4_hdr)->source);
  } else {
    h_dport = bpf_ntohs(((struct udphdr *)l4_hdr)->dest);
    h_sport = bpf_ntohs(((struct udphdr *)l4_hdr)->source);
  }
  // Redirect all DNS packet to control plane.
  if (_network == NETWORK_TYPE_UDP && h_dport == 53) {
    return OUTBOUND_CONTROL_PLANE_ROUTE;
  }
  struct lpm_key lpm_key_saddr, lpm_key_daddr, lpm_key_mac, *lpm_key;
  lpm_key_saddr.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
  lpm_key_daddr.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
  lpm_key_mac.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
  __builtin_memcpy(lpm_key_saddr.data, saddr, IPV6_BYTE_LENGTH);
  __builtin_memcpy(lpm_key_daddr.data, daddr, IPV6_BYTE_LENGTH);
  __builtin_memcpy(lpm_key_mac.data, mac, IPV6_BYTE_LENGTH);

  struct map_lpm_type *lpm;
  struct routing *routing;
  // Rule is like: domain(domain:baidu.com) && port(443) -> proxy
  bool bad_rule = false;
  struct domain_routing *domain_routing;

  /// DEPRECATED: Epoch was deprecated and domain_routing_map was unpinned, thus
  /// this branch will never hit.
  // if (domain_routing && domain_routing->epoch != *epoch) {
  //   // Dirty (epoch dismatch) traffic should be routed by the control plane.
  //   return OUTBOUND_CONTROL_PLANE_ROUTE;
  // }

#pragma unroll
  for (__u32 key = 0; key < MAX_ROUTING_LEN; key++) {
    __u32 k = key; // Clone to pass code checker.
    routing = bpf_map_lookup_elem(&routing_map, &k);
    if (!routing) {
      return -EFAULT;
    }
    if (bad_rule) {
      goto before_next_loop;
    }
    /// NOTICE: switch is not implemented efficiently by clang yet.
    if (likely(routing->type == ROUTING_TYPE_IP_SET)) {
      lpm_key = &lpm_key_saddr;
      goto lookup_lpm;
    } else if (routing->type == ROUTING_TYPE_SOURCE_IP_SET) {
      lpm_key = &lpm_key_daddr;
    lookup_lpm:
      lpm = bpf_map_lookup_elem(&lpm_array_map, &routing->index);
      if (unlikely(!lpm)) {
        return -EFAULT;
      }
      if (!bpf_map_lookup_elem(lpm, lpm_key)) {
        // Routing not hit.
        bad_rule = true;
      }
    } else if (routing->type == ROUTING_TYPE_DOMAIN_SET) {
      // Bottleneck of insns limit.
      // We fixed it by invoking bpf_map_lookup_elem here.

      // Get domain routing bitmap.
      domain_routing = bpf_map_lookup_elem(&domain_routing_map, daddr);
      if (!domain_routing) {
        // No domain corresponding to IP.
        bad_rule = true;
        goto before_next_loop;
      }

      // We use key instead of k to pass checker.
      if (!((domain_routing->bitmap[key / 32] >> (key % 32)) & 1)) {
        bad_rule = true;
      }
    } else if (routing->type == ROUTING_TYPE_PORT) {
      if (h_dport < routing->port_range.port_start ||
          h_dport > routing->port_range.port_end) {
        bad_rule = true;
      }
    } else if (routing->type == ROUTING_TYPE_SOURCE_PORT) {
      if (h_sport < routing->port_range.port_start ||
          h_sport > routing->port_range.port_end) {
        bad_rule = true;
      }
    } else if (routing->type == ROUTING_TYPE_NETWORK) {
      if (!(_network & routing->network_type)) {
        bad_rule = true;
      }
    } else if (routing->type == ROUTING_TYPE_IPVERSION) {
      if (!(_ipversion & routing->ip_version)) {
        bad_rule = true;
      }
    } else if (routing->type == ROUTING_TYPE_MAC) {
      /// FIXME: Bottleneck of insns limit. Reason: don't know.
      lpm_key = &lpm_key_mac;
      goto lookup_lpm;
    } else if (routing->type == ROUTING_TYPE_FINAL) {
      return routing->outbound;
    } else {
      return -EINVAL;
    }

  before_next_loop:
    if (routing->outbound != OUTBOUND_LOGICAL_AND) {
      // Tail of a rule (line).
      // Decide whether to hit.
      if (!bad_rule) {
        return routing->outbound;
      }
      bad_rule = false;
    }
  }
  return -EPERM;
#undef _network
#undef _ip_version
}

// Do DNAT.
SEC("tc/ingress")
int tproxy_ingress(struct __sk_buff *skb) {
  struct ethhdr *ethh;
  struct iphdr *iph;
  struct ipv6hdr *ipv6h;
  struct tcphdr *tcph;
  struct udphdr *udph;
  __sum16 bak_cksm;
  __u8 ihl;
  long ret = parse_transport(skb, &ethh, &iph, &ipv6h, &tcph, &udph, &ihl);
  if (ret) {
    bpf_printk("parse_transport: %ld", ret);
    return TC_ACT_OK;
  }
  // if (ipv6hdr) {
  //   bpf_printk("DEBUG: ipv6");
  // }

  // Backup for further use.
  __u8 l4_proto;
  if (tcph) {
    l4_proto = IPPROTO_TCP;
  } else if (udph) {
    l4_proto = IPPROTO_UDP;
  } else {
    return TC_ACT_OK;
  }

  // Parse saddr and daddr as ipv6 format.
  __be32 saddr[4];
  __be32 daddr[4];
  if (iph) {
    saddr[0] = 0;
    saddr[1] = 0;
    saddr[2] = bpf_ntohl(0xffff);
    saddr[3] = iph->saddr;

    daddr[0] = 0;
    daddr[1] = 0;
    daddr[2] = bpf_ntohl(0xffff);
    daddr[3] = iph->daddr;
  } else if (ipv6h) {
    __builtin_memcpy(daddr, &ipv6h->daddr, IPV6_BYTE_LENGTH);
    __builtin_memcpy(saddr, &ipv6h->saddr, IPV6_BYTE_LENGTH);
  } else {
    return TC_ACT_OK;
  }

  // If this packet is sent to this host, accept it.
  __u32 first_interface_ip[4];
  long to_host = ip_is_host(ipv6h, skb->ifindex, daddr, &first_interface_ip);
  if (to_host < 0) { // error
    // bpf_printk("to_host: %ld", to_host);
    return TC_ACT_OK;
  }
  if (to_host == 1) {
    if (udph && udph->dest == 53) {
      // To host:53. Process it.
    } else {
      // To host. Accept.
      /// FIXME: all host ip.
      return TC_ACT_OK;
    }
  }

  __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
  if (!tproxy_port) {
    return TC_ACT_OK;
  }

  if (tcph) {
    // Backup for further use.
    bak_cksm = tcph->check;
    bool tcp_state_syn = tcph->syn && !tcph->ack;
    struct ip_port_proto key_src;
    __builtin_memset(&key_src, 0, sizeof(key_src));
    __builtin_memcpy(key_src.ip, saddr, IPV6_BYTE_LENGTH);
    key_src.port = tcph->source;
    key_src.proto = l4_proto;
    __u8 outbound;
    // No record. No DNS requests before.
    if (unlikely(tcp_state_syn)) {
      // New TCP connection.
      // bpf_printk("[%X]New Connection", bpf_ntohl(tcph->seq));
      __u8 flag[2] = {NETWORK_TYPE_TCP}; // TCP
      if (ipv6h) {
        flag[1] = IPVERSION_6;
      } else {
        flag[1] = IPVERSION_4;
      }
      __be32 mac[4];
      __builtin_memset(mac, 0, IPV6_BYTE_LENGTH);
      __builtin_memcpy(mac, ethh->h_source, sizeof(ethh->h_source));
      if ((ret = routing(flag, tcph, saddr, daddr, mac)) < 0) {
        bpf_printk("shot routing: %ld", ret);
        return TC_ACT_SHOT;
      }

      outbound = ret;
    } else {
      // bpf_printk("[%X]Old Connection", bpf_ntohl(tcph->seq));
      // The TCP connection exists.
      struct ip_port_outbound *dst = bpf_map_lookup_elem(&dst_map, &key_src);
      if (!dst) {
        // Do not impact previous connections.
        return TC_ACT_OK;
      }
      outbound = dst->outbound;
    }

    bpf_printk("tcp: outbound: %u, %pI6", outbound, daddr);
    if (outbound == OUTBOUND_DIRECT) {
      return TC_ACT_OK;
    } else {
      // Rewrite to control plane.

      if (unlikely(tcp_state_syn)) {
        struct ip_port_outbound value_dst;
        __builtin_memset(&value_dst, 0, sizeof(value_dst));
        __builtin_memcpy(value_dst.ip, daddr, IPV6_BYTE_LENGTH);
        value_dst.port = tcph->dest;
        value_dst.outbound = outbound;
        bpf_map_update_elem(&dst_map, &key_src, &value_dst, BPF_ANY);
      }

      __u32 *dst_ip = daddr;
      __u16 dst_port = tcph->dest;
      if ((ret = rewrite_ip(skb, ipv6h, IPPROTO_TCP, ihl, dst_ip,
                            first_interface_ip, true))) {
        bpf_printk("Shot IP: %ld", ret);
        return TC_ACT_SHOT;
      }
      if ((ret = rewrite_port(skb, IPPROTO_TCP, ihl, dst_port, *tproxy_port,
                              true))) {
        bpf_printk("Shot Port: %ld", ret);
        return TC_ACT_SHOT;
      }
    }
  } else if (udph) {
    // Backup for further use.
    bak_cksm = udph->check;
    struct ip_port_outbound new_hdr;
    __builtin_memset(&new_hdr, 0, sizeof(new_hdr));
    __builtin_memcpy(new_hdr.ip, daddr, IPV6_BYTE_LENGTH);
    new_hdr.port = udph->dest;

    // Routing. It decides if we redirect traffic to control plane.
    __u8 flag[2] = {NETWORK_TYPE_UDP};
    if (ipv6h) {
      flag[1] = IPVERSION_6;
    } else {
      flag[1] = IPVERSION_4;
    }
    __be32 mac[4];
    __builtin_memset(mac, 0, IPV6_BYTE_LENGTH);
    __builtin_memcpy(mac, ethh->h_source, sizeof(ethh->h_source));
    if ((ret = routing(flag, udph, saddr, daddr, mac)) < 0) {
      bpf_printk("shot routing: %ld", ret);
      return TC_ACT_SHOT;
    }
    new_hdr.outbound = ret;
    bpf_printk("udp: outbound: %u, %pI6", new_hdr.outbound, daddr);

    if (new_hdr.outbound == OUTBOUND_DIRECT) {
      return TC_ACT_OK;
    } else {
      // Rewrite to control plane.

      // Encap a header to transmit fullcone tuple.
      __be16 ip_tot_len = iph ? iph->tot_len : 0;
      encap_after_udp_hdr(skb, ipv6h, ihl, ip_tot_len, &new_hdr,
                          sizeof(new_hdr));

      // Rewrite udp dst ip.
      // bpf_printk("rewrite dst ip from %pI4", &ori_dst.ip);
      if ((ret = rewrite_ip(skb, ipv6h, IPPROTO_UDP, ihl, new_hdr.ip,
                            first_interface_ip, true))) {
        bpf_printk("Shot IP: %ld", ret);
        return TC_ACT_SHOT;
      }

      // Rewrite udp dst port.
      if ((ret = rewrite_port(skb, IPPROTO_UDP, ihl, new_hdr.port, *tproxy_port,
                              true))) {
        bpf_printk("Shot Port: %ld", ret);
        return TC_ACT_SHOT;
      }
    }
  }

  if (udph || tcph) {
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
      __u32 l4_cksm_off = l4_checksum_off(l4_proto, ihl);
      // Restore the checksum or set it zero.
      if (*disable_l4_checksum == DISABLE_L4_CHECKSUM_POLICY_SET_ZERO) {
        bak_cksm = 0;
      }
      bpf_skb_store_bytes(skb, l4_cksm_off, &bak_cksm, sizeof(bak_cksm), 0);
    }
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
  struct ethhdr *ethh;
  struct iphdr *iph;
  struct ipv6hdr *ipv6h;
  struct tcphdr *tcph;
  struct udphdr *udph;
  __sum16 bak_cksm;
  __u8 ihl;
  long ret = parse_transport(skb, &ethh, &iph, &ipv6h, &tcph, &udph, &ihl);
  if (ret) {
    return TC_ACT_OK;
  }

  // Parse saddr and daddr as ipv6 format.
  __be32 saddr[4];
  __be32 daddr[4];
  if (iph) {
    saddr[0] = 0;
    saddr[1] = 0;
    saddr[2] = bpf_ntohl(0xffff);
    saddr[3] = iph->saddr;

    daddr[0] = 0;
    daddr[1] = 0;
    daddr[2] = bpf_ntohl(0xffff);
    daddr[3] = iph->daddr;
  } else if (ipv6h) {
    __builtin_memcpy(daddr, ipv6h->daddr.in6_u.u6_addr32, IPV6_BYTE_LENGTH);
    __builtin_memcpy(saddr, ipv6h->saddr.in6_u.u6_addr32, IPV6_BYTE_LENGTH);
  } else {
    return TC_ACT_OK;
  }

  // If not from tproxy, accept it.
  __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
  if (!tproxy_port) {
    return TC_ACT_OK;
  }
  long from_host = ip_is_host(ipv6h, skb->ifindex, saddr, NULL);
  if (!(from_host == 1)) {
    // Not from localhost.
    return TC_ACT_OK;
  }

  // Backup for further use.
  __u8 l4_proto;
  if (tcph) {
    l4_proto = IPPROTO_TCP;
  } else if (udph) {
    l4_proto = IPPROTO_UDP;
  } else {
    return TC_ACT_OK;
  }

  if (tcph) {
    if (tcph->source != *tproxy_port) {
      return TC_ACT_OK;
    }

    // Lookup original dest.
    struct ip_port_proto key_dst;
    __builtin_memset(&key_dst, 0, sizeof(key_dst));
    __builtin_memcpy(key_dst.ip, daddr, IPV6_BYTE_LENGTH);
    key_dst.proto = l4_proto;
    if (tcph) {
      key_dst.port = tcph->dest;
    } else if (udph) {
      key_dst.port = udph->dest;
    }
    struct ip_port_outbound *original_dst =
        bpf_map_lookup_elem(&dst_map, &key_dst);
    if (!original_dst) {
      bpf_printk("[%X]Bad Connection: to: %pI4:%u", bpf_ntohl(tcph->seq),
                 &key_dst.ip, bpf_ntohs(key_dst.port));
      // Do not impact previous connections.
      return TC_ACT_SHOT;
    }

    // Backup for further use.
    bak_cksm = tcph->check;

    __u32 *src_ip = saddr;
    __u16 src_port = tcph->source;
    if (rewrite_ip(skb, ipv6h, IPPROTO_TCP, ihl, src_ip, original_dst->ip,
                   false) < 0) {
      bpf_printk("Shot IP: %ld", ret);
      return TC_ACT_SHOT;
    }
    if (rewrite_port(skb, IPPROTO_TCP, ihl, src_port, original_dst->port,
                     false) < 0) {
      bpf_printk("Shot Port: %ld", ret);
      return TC_ACT_SHOT;
    }
  } else if (udph) {
    if (udph->source != *tproxy_port) {
      return TC_ACT_OK;
    }

    // Backup for further use.
    bak_cksm = udph->check;
    __u32 *src_ip = saddr;
    __u16 src_port = udph->source;
    /// NOTICE: Actually, we do not need symmetrical headers in client and
    /// server. We use it for convinience. This behavior may change in the
    /// future. Outbound here is useless and redundant.
    struct ip_port_outbound ori_src;
    __builtin_memset(&ori_src, 0, sizeof(ori_src));

    // Get source ip/port from our packet header.

    // Decap header to get fullcone tuple.
    __be16 ip_tot_len = iph ? iph->tot_len : 0;
    decap_after_udp_hdr(skb, ipv6h, ihl, ip_tot_len, &ori_src, sizeof(ori_src));

    // Rewrite udp src ip
    if ((ret = rewrite_ip(skb, ipv6h, IPPROTO_UDP, ihl, src_ip, ori_src.ip,
                          false))) {
      bpf_printk("Shot IP: %ld", ret);
      return TC_ACT_SHOT;
    }

    // Rewrite udp src port
    if ((ret = rewrite_port(skb, IPPROTO_UDP, ihl, src_port, ori_src.port,
                            false))) {
      bpf_printk("Shot Port: %ld", ret);
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

  if (udph || tcph) {
    __u8 *disable_l4_checksum =
        bpf_map_lookup_elem(&param_map, &disable_l4_tx_checksum_key);
    if (!disable_l4_checksum) {
      bpf_printk("Forgot to set disable_l4_checksum?");
      return TC_ACT_SHOT;
    }
    if (*disable_l4_checksum) {
      __u32 l4_cksm_off = l4_checksum_off(l4_proto, ihl);
      // Restore the checksum or set it zero.
      if (*disable_l4_checksum == DISABLE_L4_CHECKSUM_POLICY_SET_ZERO) {
        bak_cksm = 0;
      }
      bpf_skb_store_bytes(skb, l4_cksm_off, &bak_cksm, 2, 0);
    }
  }
  return TC_ACT_OK;
}

SEC("license") const char __license[] = "Dual BSD/GPL";