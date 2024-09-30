// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>

//go:build exclude

#define __DEBUG
#define __DEBUG_ROUTING
#define __PRINT_ROUTING_RESULT

#include "../tproxy.c"

#define IP4_HLEN sizeof(struct iphdr)
#define IP6_HLEN sizeof(struct ipv6hdr)
#define TCP_HLEN sizeof(struct tcphdr)

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map SEC(".maps") = {
	.values = {
		[0] = &tproxy_wan_egress,
	},
};

SEC("tc/pktgen/port_match")
int testpktgen_port_match(struct __sk_buff *skb)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + TCP_HLEN, 0);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	eth->h_proto = bpf_htons(ETH_P_IP);

	struct iphdr *ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	ip->ihl = 5;
	ip->version = 4;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = bpf_htonl(0xc0a80001); // 192.168.0.1
	ip->daddr = bpf_htonl(0x01010101); // 1.1.1.1

	struct tcphdr *tcp = data + ETH_HLEN + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	tcp->source = bpf_htons(19233);
	tcp->dest = bpf_htons(80);
	tcp->syn = 1;

	return TC_ACT_OK;
}

SEC("tc/setup/port_match")
int testsetup_port_match(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* dport(80) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {80, 80};
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = 2;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	__builtin_memset(&ms.__value, 0, sizeof(ms.__value));
	ms.not = false;
	ms.type = MatchType_Fallback;
	ms.outbound = 0;
	ms.must = true;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &one_key, &ms, BPF_ANY);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/port_match")
int testcheck_port_match(struct __sk_buff *skb)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != TC_ACT_REDIRECT) {
		bpf_printk("status_code(%d) != TC_ACT_REDIRECT\n", *status_code);
		return TC_ACT_SHOT;
	}

	if (skb->cb[0] != TPROXY_MARK) {
		bpf_printk("skb->cb[0] != TPROXY_MARK\n");
		return TC_ACT_SHOT;
	}

	if (skb->cb[1] != IPPROTO_TCP) {
		bpf_printk("skb->cb[1] != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}

	struct ethhdr *eth = data + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_printk("eth->h_proto != 0x0800\n");
		return TC_ACT_SHOT;
	}

	struct iphdr *ip = (void *)eth + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip->protocol != IPPROTO_TCP) {
		bpf_printk("ip->protocol != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}
	if (ip->daddr != bpf_htonl(0x01010101)) {
		bpf_printk("ip->daddr != 1.1.1.1\n");
		return TC_ACT_SHOT;
	}

	struct tcphdr *tcp = (void *)ip + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (tcp->dest != bpf_htons(80)) {
		bpf_printk("tcp->dest != 80\n");
		return TC_ACT_SHOT;
	}

	struct tuples tuples = {};
	tuples.five.sip.u6_addr32[2] = bpf_htonl(0xffff);
	tuples.five.sip.u6_addr32[3] = ip->saddr;
	tuples.five.dip.u6_addr32[2] = bpf_htonl(0xffff);
	tuples.five.dip.u6_addr32[3] = ip->daddr;
	tuples.five.sport = tcp->source;
	tuples.five.dport = tcp->dest;
	tuples.five.l4proto = ip->protocol;

	struct routing_result *routing_result;
	routing_result = bpf_map_lookup_elem(&routing_tuples_map, &tuples.five);
	if (!routing_result) {
		bpf_printk("routing_result == NULL\n");
		return TC_ACT_SHOT;
	}

	if (routing_result->mark != 0) {
		bpf_printk("routing_result->mark != 0\n");
		return TC_ACT_SHOT;
	}

	if (routing_result->must != 0) {
		bpf_printk("routing_result->must != 0\n");
		return TC_ACT_SHOT;
	}

	if (routing_result->outbound != 2) {
		bpf_printk("routing_result->outbound != 2\n");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

SEC("tc/pktgen/port_mismatch")
int testpktgen_port_mismatch(struct __sk_buff *skb)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + TCP_HLEN, 0);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	eth->h_proto = bpf_htons(ETH_P_IP);

	struct iphdr *ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	ip->ihl = 5;
	ip->version = 4;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = bpf_htonl(0xc0a80001); // 192.168.0.1
	ip->daddr = bpf_htonl(0x01010101); // 1.1.1.1

	struct tcphdr *tcp = data + ETH_HLEN + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	tcp->source = bpf_htons(19233);
	tcp->dest = bpf_htons(79);
	tcp->syn = 1;

	return TC_ACT_OK;
}

SEC("tc/setup/port_mismatch")
int testsetup_port_mismatch(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* dport(80) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {80, 80};
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = 2;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	__builtin_memset(&ms.__value, 0, sizeof(ms.__value));
	ms.not = false;
	ms.type = MatchType_Fallback;
	ms.outbound = 0;
	ms.must = true;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &one_key, &ms, BPF_ANY);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/port_mismatch")
int testcheck_port_mismatch(struct __sk_buff *skb)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != TC_ACT_OK) {
		bpf_printk("status_code(%d) != TC_ACT_OK\n", *status_code);
		return TC_ACT_SHOT;
	}

	struct ethhdr *eth = data + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_printk("eth->h_proto != 0x0800\n");
		return TC_ACT_SHOT;
	}

	struct iphdr *ip = (void *)eth + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip->protocol != IPPROTO_TCP) {
		bpf_printk("ip->protocol != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}
	if (ip->daddr != bpf_htonl(0x01010101)) {
		bpf_printk("ip->daddr != 1.1.1.1\n");
		return TC_ACT_SHOT;
	}

	struct tcphdr *tcp = (void *)ip + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (tcp->dest != bpf_htons(79)) {
		bpf_printk("tcp->dest != 79\n");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

SEC("tc/pktgen/ipset_match_v4")
int testpktgen_ipset_match_v4(struct __sk_buff *skb)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + TCP_HLEN, 0);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	eth->h_proto = bpf_htons(ETH_P_IP);

	struct iphdr *ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	ip->ihl = 5;
	ip->version = 4;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = bpf_htonl(0xc0a80001); // 192.168.0.1
	ip->daddr = bpf_htonl(0xe0010002); // 224.1.0.2

	struct tcphdr *tcp = data + ETH_HLEN + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	tcp->source = bpf_htons(19233);
	tcp->dest = bpf_htons(80);
	tcp->syn = 1;

	return TC_ACT_OK;
}

SEC("tc/setup/ipset_match_v4")
int testsetup_ipset_match_v4(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* dip(224.0.0.0/8, 'ff00::/8') -> direct */
	struct match_set ms = {};
	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {};
	lpm_key.trie_key.prefixlen = 112;
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0xe0010000); // 224.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	__builtin_memset(&lpm_key, 0, sizeof(lpm_key));
	lpm_key.trie_key.prefixlen = 8;
	lpm_key.data[0] = bpf_ntohl(0xff000000); // ff00::
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	__builtin_memset(&ms.__value, 0, sizeof(ms.__value));
	ms.not = false;
	ms.type = MatchType_Fallback;
	ms.outbound = 2;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &one_key, &ms, BPF_ANY);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipset_match_v4")
int testcheck_ipset_match_v4(struct __sk_buff *skb)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != TC_ACT_OK) {
		bpf_printk("status_code(%d) != TC_ACT_OK\n", *status_code);
		return TC_ACT_SHOT;
	}

	struct ethhdr *eth = data + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_printk("eth->h_proto != 0x0800\n");
		return TC_ACT_SHOT;
	}

	struct iphdr *ip = (void *)eth + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip->protocol != IPPROTO_TCP) {
		bpf_printk("ip->protocol != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}
	if (ip->daddr != bpf_htonl(0xe0010002)) {
		bpf_printk("ip->daddr != 224.1.0.2\n");
		return TC_ACT_SHOT;
	}

	struct tcphdr *tcp = (void *)ip + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (tcp->dest != bpf_htons(80)) {
		bpf_printk("tcp->dest != 80\n");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

SEC("tc/pktgen/ipset_match_v6")
int testpktgen_ipset_match_v6(struct __sk_buff *skb)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP6_HLEN + TCP_HLEN, 0);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	struct ipv6hdr *ip6 = data + ETH_HLEN;
	if ((void *)(ip6 + 1) > data_end) {
		bpf_printk("data + sizeof(*ip6) > data_end\n");
		return TC_ACT_SHOT;
	}
	ip6->version = 6;
	ip6->nexthdr = IPPROTO_TCP;
	__builtin_memset(&ip6->saddr, 0, sizeof(ip6->saddr));
	ip6->saddr.in6_u.u6_addr32[0] = bpf_htonl(0x20010db8); // 2001:db8::
	ip6->saddr.in6_u.u6_addr32[3] = bpf_htonl(0x1); // 2001:db8::1
	__builtin_memset(&ip6->daddr, 0, sizeof(ip6->daddr));
	ip6->daddr.in6_u.u6_addr32[0] = bpf_htonl(0xff000000); // ff00::
	ip6->daddr.in6_u.u6_addr32[3] = bpf_htonl(0x2); // ff00::2

	struct tcphdr *tcp = data + ETH_HLEN + IP6_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	tcp->source = bpf_htons(19233);
	tcp->dest = bpf_htons(80);
	tcp->syn = 1;

	return TC_ACT_OK;
}

SEC("tc/setup/ipset_match_v6")
int testsetup_ipset_match_v6(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* dip(224.0.0.0/8, 'ff00::/8') -> direct */
	struct match_set ms = {};
	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {};
	lpm_key.trie_key.prefixlen = 112;
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0xe0010000); // 224.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	__builtin_memset(&lpm_key, 0, sizeof(lpm_key));
	lpm_key.trie_key.prefixlen = 8;
	lpm_key.data[0] = bpf_ntohl(0xff000000); // ff00::
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	__builtin_memset(&ms.__value, 0, sizeof(ms.__value));
	ms.not = false;
	ms.type = MatchType_Fallback;
	ms.outbound = 2;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &one_key, &ms, BPF_ANY);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipset_match_v6")
int testcheck_ipset_match_v6(struct __sk_buff *skb)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != TC_ACT_OK) {
		bpf_printk("status_code(%d) != TC_ACT_OK\n", *status_code);
		return TC_ACT_SHOT;
	}

	struct ethhdr *eth = data + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IPV6)) {
		bpf_printk("eth->h_proto != ETH_P_IPV6\n");
		return TC_ACT_SHOT;
	}

	struct ipv6hdr *ip6 = (void *)eth + ETH_HLEN;
	if ((void *)(ip6 + 1) > data_end) {
		bpf_printk("data + sizeof(*ip6) > data_end\n");
		return TC_ACT_SHOT;
	}

	if (ip6->nexthdr != IPPROTO_TCP) {
		bpf_printk("ip6->next_header != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}

	if (ip6->daddr.in6_u.u6_addr32[0] != bpf_htonl(0xff000000)) {
		bpf_printk("ip6->daddr.in6_u.u6_addr32[0] != 0xff000000\n");
		return TC_ACT_SHOT;
	}

	struct tcphdr *tcp = (void *)ip6 + IP6_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (tcp->dest != bpf_htons(80)) {
		bpf_printk("tcp->dest != 80\n");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

SEC("tc/pktgen/ipset_mismatch")
int testpktgen_ipset_mismatch(struct __sk_buff *skb)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + TCP_HLEN, 0);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	eth->h_proto = bpf_htons(ETH_P_IP);

	struct iphdr *ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	ip->ihl = 5;
	ip->version = 4;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = bpf_htonl(0xc0a80001); // 192.168.0.1
	ip->daddr = bpf_htonl(0xe1010002); // 225.1.0.2

	struct tcphdr *tcp = data + ETH_HLEN + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	tcp->source = bpf_htons(19233);
	tcp->dest = bpf_htons(80);
	tcp->syn = 1;

	return TC_ACT_OK;
}

SEC("tc/setup/ipset_mismatch")
int testsetup_ipset_mismatch(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* dip(224.0.0.0/8, 'ff00::/8') -> direct */
	struct match_set ms = {};
	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {};
	lpm_key.trie_key.prefixlen = 112;
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0xe0010000); // 224.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	__builtin_memset(&lpm_key, 0, sizeof(lpm_key));
	lpm_key.trie_key.prefixlen = 8;
	lpm_key.data[0] = bpf_ntohl(0xff000000); // ff00::
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	__builtin_memset(&ms.__value, 0, sizeof(ms.__value));
	ms.not = false;
	ms.type = MatchType_Fallback;
	ms.outbound = 2;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &one_key, &ms, BPF_ANY);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipset_mismatch")
int testcheck_ipset_mismatch(struct __sk_buff *skb)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != TC_ACT_REDIRECT) {
		bpf_printk("status_code(%d) != TC_ACT_REDIRECT\n", *status_code);
		return TC_ACT_SHOT;
	}

	struct ethhdr *eth = data + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_printk("eth->h_proto != 0x0800\n");
		return TC_ACT_SHOT;
	}

	struct iphdr *ip = (void *)eth + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip->protocol != IPPROTO_TCP) {
		bpf_printk("ip->protocol != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}
	if (ip->daddr != bpf_htonl(0xe1010002)) {
		bpf_printk("ip->daddr != 225.1.0.2\n");
		return TC_ACT_SHOT;
	}

	struct tcphdr *tcp = (void *)ip + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (tcp->dest != bpf_htons(80)) {
		bpf_printk("tcp->dest != 80\n");
		return TC_ACT_SHOT;
	}

	struct tuples tuples = {};
	tuples.five.sip.u6_addr32[2] = bpf_htonl(0xffff);
	tuples.five.sip.u6_addr32[3] = ip->saddr;
	tuples.five.dip.u6_addr32[2] = bpf_htonl(0xffff);
	tuples.five.dip.u6_addr32[3] = ip->daddr;
	tuples.five.sport = tcp->source;
	tuples.five.dport = tcp->dest;
	tuples.five.l4proto = ip->protocol;

	struct routing_result *routing_result;
	routing_result = bpf_map_lookup_elem(&routing_tuples_map, &tuples.five);
	if (!routing_result) {
		bpf_printk("routing_result == NULL\n");
		return TC_ACT_SHOT;
	}

	if (routing_result->mark != 0) {
		bpf_printk("routing_result->mark != 0\n");
		return TC_ACT_SHOT;
	}

	if (routing_result->must != 0) {
		bpf_printk("routing_result->must != 0\n");
		return TC_ACT_SHOT;
	}

	if (routing_result->outbound != 2) {
		bpf_printk("routing_result->outbound != 2\n");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}
