#include "headers/if_ether_defs.h"
#include "headers/vmlinux.h"

#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"

#define IFNAMSIZ 16
#define PNAME_LEN 32

static const bool TRUE = true;

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
	u16 payload_len;
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

static volatile const struct tracing_config tracing_cfg;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, bool);
	__uint(max_entries, 1024);
} skb_addresses SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<29);
} events SEC(".maps");

static __always_inline u32
get_netns(struct sk_buff *skb)
{
	u32 netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);

	// if skb->dev is not initialized, try to get ns from sk->__sk_common.skc_net.net->ns.inum
	if (netns == 0)	{
		struct sock *sk = BPF_CORE_READ(skb, sk);
		if (sk != NULL)
			netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	}

	return netns;
}

static __always_inline bool
filter_l3_and_l4(struct sk_buff *skb)
{
	void *skb_head = BPF_CORE_READ(skb, head);
	u16 l3_off = BPF_CORE_READ(skb, network_header);
	u16 l4_off = BPF_CORE_READ(skb, transport_header);

	struct iphdr *l3_hdr = (struct iphdr *) (skb_head + l3_off);
	u8 ip_vsn = BPF_CORE_READ_BITFIELD_PROBED(l3_hdr, version);
	if (ip_vsn != tracing_cfg.ip_vsn)
		return false;

	u16 l4_proto;
	if (ip_vsn == 4) {
		struct iphdr *ip4 = (struct iphdr *) l3_hdr;
		l4_proto = BPF_CORE_READ(ip4, protocol);
	} else if (ip_vsn == 6) {
		struct ipv6hdr *ip6 = (struct ipv6hdr *) l3_hdr;
		l4_proto = BPF_CORE_READ(ip6, nexthdr);
	} else {
		return false;
	}

	if (l4_proto != tracing_cfg.l4_proto)
		return false;

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

	if (dport != tracing_cfg.port && sport != tracing_cfg.port)
		return false;

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

	struct iphdr *l3_hdr = (struct iphdr *) (skb_head + l3_off);
	u8 ip_vsn = BPF_CORE_READ_BITFIELD_PROBED(l3_hdr, version);

	u16 l3_total_len;
	if (ip_vsn == 4) {
		struct iphdr *ip4 = (struct iphdr *) l3_hdr;
		BPF_CORE_READ_INTO(&tpl->saddr, ip4, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip4, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip4, protocol);
		tpl->l3_proto = ETH_P_IP;
		l3_total_len = bpf_ntohs(BPF_CORE_READ(ip4, tot_len));
	} else if (ip_vsn == 6) {
		struct ipv6hdr *ip6 = (struct ipv6hdr *) l3_hdr;
		BPF_CORE_READ_INTO(&tpl->saddr, ip6, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip6, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip6, nexthdr);
		tpl->l3_proto = ETH_P_IPV6;
		l3_total_len = bpf_ntohs(BPF_CORE_READ(ip6, payload_len));
	}
	u16 l3_hdr_len = l4_off - l3_off;

	u16 l4_hdr_len;
	if (tpl->l4_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) (skb_head + l4_off);
		tpl->sport= BPF_CORE_READ(tcp, source);
		tpl->dport= BPF_CORE_READ(tcp, dest);
		bpf_probe_read_kernel(&tpl->tcp_flags, sizeof(tpl->tcp_flags),
				    tcp + offsetof(struct tcphdr, ack_seq) + 5);
		l4_hdr_len = BPF_CORE_READ_BITFIELD_PROBED(tcp, doff) * 4;
		tpl->payload_len = l3_total_len - l3_hdr_len - l4_hdr_len;
	} else if (tpl->l4_proto == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *) (skb_head + l4_off);
		tpl->sport= BPF_CORE_READ(udp, source);
		tpl->dport= BPF_CORE_READ(udp, dest);
		tpl->payload_len = bpf_ntohs(BPF_CORE_READ(udp, len)) - sizeof(struct udphdr);
	}
}

static __always_inline int
handle_skb(struct sk_buff *skb, struct pt_regs *ctx)
{
	bool tracked = false;
	u64 skb_addr = (u64) skb;
	struct event ev = {};
	if (bpf_map_lookup_elem(&skb_addresses, &skb_addr)) {
		tracked = true;
		goto cont;
	}

	if (!filter_l3_and_l4(skb))
		return 0;

	if (!tracked)
		bpf_map_update_elem(&skb_addresses, &skb_addr, &TRUE, BPF_ANY);

cont:
	set_meta(&ev.meta, skb, ctx);
	set_tuple(&ev.tuple, skb);

	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
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
	return 0;
}

SEC("license") const char __license[] = "Dual BSD/GPL";
