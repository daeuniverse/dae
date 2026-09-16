// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>

#include "headers/if_ether_defs.h"
#include "headers/vmlinux.h"

#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"

#define IFNAMSIZ 16
#define PNAME_LEN 32

static const bool TRUE = true;

enum trace_stat {
	TRACE_STAT_HANDLE_SKB,
	TRACE_STAT_FILTER_FAIL,
	TRACE_STAT_MATCH,
	TRACE_STAT_RINGBUF_FAIL,
	TRACE_STAT_DELETE,
	TRACE_STAT_IP_VERSION_FAIL,
	TRACE_STAT_L4_PROTO_FAIL,
	TRACE_STAT_PORT_FAIL,
	TRACE_STAT_L4_UNKNOWN,
	TRACE_STAT_MAX,
};

/* The L4 protocol could not be determined (truncated header, unreadable
 * extension header chain, non-initial fragment). 0xff is not a transport
 * protocol this tracer matches, so a failed read can no longer masquerade as a
 * real protocol value and satisfy the filter. */
#define TRACE_L4_UNKNOWN 0xff

/* The payload length cannot be derived from the headers (GSO skbs carry
 * tot_len == 0). Encoded explicitly instead of wrapping around in a u16. */
#define TRACE_PAYLOAD_LEN_UNKNOWN 0xffffffffU

union addr {
	u32 v4addr;
	struct {
		u64 d1;
		u64 d2;
	} v6addr;
} __attribute__((packed));

struct meta {
	u64 pc;
	u64 skb;
	u64 second_param;
	u32 mark;
	u32 netns;
	u32 ifindex;
	u32 pid;
	unsigned char ifname[IFNAMSIZ];
	unsigned char pname[PNAME_LEN];
} __attribute__((packed));

struct tuple {
	union addr saddr;
	union addr daddr;
	u16 sport;
	u16 dport;
	u16 l3_proto;
	u8 l4_proto;
	u8 tcp_flags;
	u32 payload_len;
} __attribute__((packed));

struct event {
	struct meta meta;
	struct tuple tuple;
} __attribute__((packed));

const struct event *_ __attribute__((unused));

struct tracing_config {
	u16 port;
	u16 l4_proto;
	u8 ip_vsn;
};

const volatile struct tracing_config tracing_cfg = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, bool);
	__uint(max_entries, 1024);
} skb_addresses SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, TRACE_STAT_MAX);
} trace_stats SEC(".maps");

static __always_inline void
inc_trace_stat(__u32 key)
{
	__u64 *value = bpf_map_lookup_elem(&trace_stats, &key);

	if (value)
		__sync_fetch_and_add(value, 1);
}

static __always_inline u32
get_netns(struct sk_buff *skb)
{
	u32 netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);

	// if skb->dev is not initialized, try to get ns from sk->__sk_common.skc_net.net->ns.inum
	if (netns == 0)	{
		struct sock *sk = BPF_CORE_READ(skb, sk);

		if (sk)
			netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	}

	return netns;
}

// skip_ipv6_exthdr walks through IPv6 extension headers (Hop-by-Hop, Routing,
// Dest Options, Fragment, Authentication Header) and returns the final L4
// protocol number, or TRACE_L4_UNKNOWN when the chain cannot be parsed.
// *off is updated to point past all extension headers.
// Bounded to 4 iterations to stay within BPF stack limits.
// NOTE: Uses bpf_probe_read_kernel + BPF_CORE_READ(skb, head) because this
// runs in kprobe context (struct sk_buff*), not TC/XDP (struct __sk_buff*).
static __always_inline __u8
skip_ipv6_exthdr(struct sk_buff *skb, __u32 *off, __u8 nexthdr)
{
	void *skb_head = BPF_CORE_READ(skb, head);

	if (!skb_head)
		return TRACE_L4_UNKNOWN;

#pragma unroll
	for (int i = 0; i < 4; i++) {
		switch (nexthdr) {
		case 0:   // Hop-by-Hop
		case 43:  // Routing
		case 60:  // Destination Options
			{
				__u8 hdrlen;

				// Next Header field is at byte 0 of the current header;
				// must be read BEFORE advancing *off.
				if (bpf_probe_read_kernel(&nexthdr, 1, skb_head + *off) < 0)
					return TRACE_L4_UNKNOWN;
				if (bpf_probe_read_kernel(&hdrlen, 1, skb_head + *off + 1) < 0)
					return TRACE_L4_UNKNOWN;
				*off += (__u32)(hdrlen + 1) * 8;
			}
			break;
		case 44:  // Fragment
			{
				__be16 frag_off;

				// Next Header field is at byte 0 of the Fragment header;
				// must be read BEFORE advancing *off.
				if (bpf_probe_read_kernel(&nexthdr, 1, skb_head + *off) < 0)
					return TRACE_L4_UNKNOWN;
				if (bpf_probe_read_kernel(&frag_off, 2, skb_head + *off + 2) < 0)
					return TRACE_L4_UNKNOWN;
				*off += 8;
				// bits 15-3 are fragment offset (13 bits); 0xFFF8 covers all of them.
				if (frag_off & bpf_htons(0xFFF8))  // offset != 0
					return TRACE_L4_UNKNOWN;  // non-first fragment, cannot parse
			}
			break;
		case 51:  // Authentication Header
			{
				__u8 hdrlen;

				if (bpf_probe_read_kernel(&nexthdr, 1, skb_head + *off) < 0)
					return TRACE_L4_UNKNOWN;
				if (bpf_probe_read_kernel(&hdrlen, 1, skb_head + *off + 1) < 0)
					return TRACE_L4_UNKNOWN;
				// RFC 4302: length in 4-octet units excluding the first 8
				// octets, matching ipv6_exthdr_len() in the datapath.
				*off += (__u32)(hdrlen + 2) * 4;
			}
			break;
		default:
			return nexthdr;
		}
	}
	return nexthdr;
}

// Reads the IP version/ihl byte raw and returns false when it is unreadable.
// The UAPI bitfield layout depends on the target endianness, not on the wire
// format, so BPF_CORE_READ_BITFIELD_PROBED would report the version nibble as
// ihl (and vice versa) on a big-endian host.
static __always_inline bool
read_ip_version_ihl(struct sk_buff *skb, void *skb_head, u16 l3_off,
		    u8 *ip_vsn, u8 *ihl)
{
	u8 version_ihl;

	if (!skb_head ||
	    bpf_probe_read_kernel(&version_ihl, 1, skb_head + l3_off))
		return false;
	*ip_vsn = version_ihl >> 4;
	*ihl = version_ihl & 0xf;
	return true;
}

static __always_inline bool
filter_l3_and_l4(struct sk_buff *skb)
{
	void *skb_head = BPF_CORE_READ(skb, head);
	u16 l3_off = BPF_CORE_READ(skb, network_header);
	u16 l4_off = BPF_CORE_READ(skb, transport_header);
	u8 ip_vsn, ihl;
	u16 l3_hdr_len;
	u16 l4_proto;

	struct iphdr *l3_hdr = (struct iphdr *) (skb_head + l3_off);

	if (!read_ip_version_ihl(skb, skb_head, l3_off, &ip_vsn, &ihl))
		return false;

	if (ip_vsn != tracing_cfg.ip_vsn) {
		inc_trace_stat(TRACE_STAT_IP_VERSION_FAIL);
		return false;
	}

	if (ip_vsn == 4) {
		struct iphdr *ip4 = (struct iphdr *) l3_hdr;

		// A malformed header cannot be walked: the transport offset would
		// point inside the IP header.
		if (ihl < 5) {
			inc_trace_stat(TRACE_STAT_L4_UNKNOWN);
			return false;
		}
		l3_hdr_len = (u16)ihl * 4;
		l4_proto = BPF_CORE_READ(ip4, protocol);
	} else if (ip_vsn == 6) {
		struct ipv6hdr *ip6 = (struct ipv6hdr *) l3_hdr;

		__u32 exthdr_off = l3_off + sizeof(struct ipv6hdr);

		l4_proto = skip_ipv6_exthdr(skb, &exthdr_off, BPF_CORE_READ(ip6, nexthdr));
		l3_hdr_len = (u16)(exthdr_off - l3_off);
	} else {
		return false;
	}

	// A parse failure is not a protocol value and must not be matched.
	if (l4_proto == TRACE_L4_UNKNOWN) {
		inc_trace_stat(TRACE_STAT_L4_UNKNOWN);
		return false;
	}

	if (l4_proto != tracing_cfg.l4_proto) {
		inc_trace_stat(TRACE_STAT_L4_PROTO_FAIL);
		return false;
	}

	// transport_header must point past the L3 headers before it is used to
	// read the ports: an unset (0) or inverted value would read unrelated
	// bytes and report a tuple that is not the packet's.
	if (l4_off < l3_off + l3_hdr_len) {
		inc_trace_stat(TRACE_STAT_L4_UNKNOWN);
		return false;
	}

	u16 sport, dport;

	if (l4_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) (skb_head + l4_off);

		sport = BPF_CORE_READ(tcp, source);
		dport = BPF_CORE_READ(tcp, dest);
	} else if (l4_proto == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *) (skb_head + l4_off);

		sport = BPF_CORE_READ(udp, source);
		dport = BPF_CORE_READ(udp, dest);
	} else {
		return false;
	}

	if (dport != tracing_cfg.port && sport != tracing_cfg.port) {
		inc_trace_stat(TRACE_STAT_PORT_FAIL);
		return false;
	}

	return true;
}

static __always_inline void
set_meta(struct meta *meta, struct sk_buff *skb, struct pt_regs *ctx)
{
	meta->pc = bpf_get_func_ip(ctx);
	meta->skb = (__u64)skb;
	meta->second_param = PT_REGS_PARM2(ctx);
	meta->mark = BPF_CORE_READ(skb, mark);
	meta->netns = get_netns(skb);
	meta->ifindex = BPF_CORE_READ(skb, dev, ifindex);
	BPF_CORE_READ_STR_INTO(&meta->ifname, skb, dev, name);

	struct task_struct *current = (void *)bpf_get_current_task();

	meta->pid = BPF_CORE_READ(current, pid);
	u64 arg_start = BPF_CORE_READ(current, mm, arg_start);

	bpf_probe_read_user_str(&meta->pname, PNAME_LEN, (void *)arg_start);
}

static __always_inline void
set_tuple(struct tuple *tpl, struct sk_buff *skb)
{
	void *skb_head = BPF_CORE_READ(skb, head);
	u16 l3_off = BPF_CORE_READ(skb, network_header);
	u16 l4_off = BPF_CORE_READ(skb, transport_header);
	u8 ip_vsn, ihl;
	u32 l3_total_len = 0;
	u16 l3_hdr_len;
	u16 l4_hdr_len;

	// Start from the explicitly unknown encoding: every early return below
	// leaves the tuple marked as unparsed instead of reporting a wrapped
	// number that looks like a real measurement.
	tpl->l4_proto = TRACE_L4_UNKNOWN;
	tpl->payload_len = TRACE_PAYLOAD_LEN_UNKNOWN;

	if (!read_ip_version_ihl(skb, skb_head, l3_off, &ip_vsn, &ihl))
		return;

	struct iphdr *l3_hdr = (struct iphdr *) (skb_head + l3_off);

	if (ip_vsn == 4) {
		struct iphdr *ip4 = (struct iphdr *) l3_hdr;

		if (ihl < 5)
			return;
		BPF_CORE_READ_INTO(&tpl->saddr, ip4, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip4, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip4, protocol);
		tpl->l3_proto = ETH_P_IP;
		l3_total_len = bpf_ntohs(BPF_CORE_READ(ip4, tot_len));
		l3_hdr_len = (u16)ihl * 4;
	} else if (ip_vsn == 6) {
		struct ipv6hdr *ip6 = (struct ipv6hdr *) l3_hdr;
		__u32 exthdr_off2 = l3_off + sizeof(struct ipv6hdr);

		BPF_CORE_READ_INTO(&tpl->saddr, ip6, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip6, daddr);
		tpl->l4_proto = skip_ipv6_exthdr(skb, &exthdr_off2, BPF_CORE_READ(ip6, nexthdr));
		tpl->l3_proto = ETH_P_IPV6;
		// payload_len excludes the 40-byte base header while l3_hdr_len
		// below counts it, so add it back: both IP versions then compute
		// payload_len from the same "whole L3 packet" quantity. Without
		// this the payload of every IPv6 packet was 40 bytes short.
		l3_total_len = (u32)sizeof(struct ipv6hdr) +
			       bpf_ntohs(BPF_CORE_READ(ip6, payload_len));
		l3_hdr_len = (u16)(exthdr_off2 - l3_off);
	} else {
		return;
	}

	if (tpl->l4_proto == TRACE_L4_UNKNOWN)
		return;
	if (l4_off < l3_off + l3_hdr_len)
		return;

	if (tpl->l4_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) (skb_head + l4_off);
		u8 doff;

		tpl->sport= BPF_CORE_READ(tcp, source);
		tpl->dport= BPF_CORE_READ(tcp, dest);
		bpf_probe_read_kernel(&tpl->tcp_flags, sizeof(tpl->tcp_flags),
				      (void *)tcp + offsetof(struct tcphdr, ack_seq) + 5);
		// The data offset nibble is at byte 12 of the header; read it raw
		// for the same reason as the IP version/ihl byte above.
		if (bpf_probe_read_kernel(&doff, 1,
					  (void *)tcp + offsetof(struct tcphdr, ack_seq) + 4))
			return;
		doff >>= 4;
		if (doff < 5)
			return;
		l4_hdr_len = (u16)doff * 4;
		// tot_len is 0 for GSO skbs, so subtract with saturation: a
		// wrapped u16 would be indistinguishable from a real length.
		if (l3_total_len > (u32)l3_hdr_len + l4_hdr_len)
			tpl->payload_len = l3_total_len - l3_hdr_len - l4_hdr_len;
	} else if (tpl->l4_proto == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *) (skb_head + l4_off);
		u16 udp_len;

		tpl->sport= BPF_CORE_READ(udp, source);
		tpl->dport= BPF_CORE_READ(udp, dest);
		udp_len = bpf_ntohs(BPF_CORE_READ(udp, len));
		if (udp_len >= sizeof(struct udphdr))
			tpl->payload_len = udp_len - sizeof(struct udphdr);
	}
}

static __always_inline int
handle_skb(struct sk_buff *skb, struct pt_regs *ctx)
{
	bool tracked = false;
	u64 skb_addr = (u64) skb;
	struct event ev = {};

	inc_trace_stat(TRACE_STAT_HANDLE_SKB);

	if (bpf_map_lookup_elem(&skb_addresses, &skb_addr)) {
		tracked = true;
		goto cont;
	}

	if (!filter_l3_and_l4(skb)) {
		inc_trace_stat(TRACE_STAT_FILTER_FAIL);
		return 0;
	}

	if (!tracked) {
		bpf_map_update_elem(&skb_addresses, &skb_addr, &TRUE, BPF_ANY);
		inc_trace_stat(TRACE_STAT_MATCH);
	}

cont:
	set_meta(&ev.meta, skb, ctx);
	set_tuple(&ev.tuple, skb);

	if (bpf_ringbuf_output(&events, &ev, sizeof(ev), 0))
		inc_trace_stat(TRACE_STAT_RINGBUF_FAIL);
	return 0;
}

#define KPROBE_SKB_AT(X)						\
  SEC("kprobe/skb-" #X)							\
  int kprobe_skb_##X(struct pt_regs *ctx)				\
  {									\
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM##X(ctx);      \
    return handle_skb(skb, ctx);					\
  }

KPROBE_SKB_AT(1)
KPROBE_SKB_AT(2)
KPROBE_SKB_AT(3)
KPROBE_SKB_AT(4)
KPROBE_SKB_AT(5)

SEC("kprobe/skb_lifetime_termination")
int kprobe_skb_lifetime_termination(struct pt_regs *ctx)
{
	u64 skb = (u64) PT_REGS_PARM1(ctx);

	bpf_map_delete_elem(&skb_addresses, &skb);
	inc_trace_stat(TRACE_STAT_DELETE);
	return 0;
}

SEC("license") const char __license[] = "Dual BSD/GPL";
