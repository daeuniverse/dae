// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

//go:build exclude

#define IP4_HLEN sizeof(struct iphdr)
#define IP6_HLEN sizeof(struct ipv6hdr)
#define TCP_HLEN sizeof(struct tcphdr)
#define IPV4_MF_FLAG 0x2000
#define FAST_PATH_PACKET_SIZE 160

#define OUTBOUND_USER_DEFINED_MIN 2

#define IPV4(a, b, c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))

static const __u32 three_key = 3;
static const __u32 four_key = 4;

static __always_inline int
set_ipv4_tcp_with_flags(struct __sk_buff *skb,
			__u32 saddr, __u32 daddr,
			__u16 sport, __u16 dport,
			bool syn, bool ack, bool psh)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + TCP_HLEN, 0);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	eth->h_dest[0] = 0x0;
	eth->h_dest[1] = 0x1;
	eth->h_dest[2] = 0x2;
	eth->h_dest[3] = 0x3;
	eth->h_dest[4] = 0x4;
	eth->h_dest[5] = 0x5;
	eth->h_source[0] = 0x6;
	eth->h_source[1] = 0x7;
	eth->h_source[2] = 0x8;
	eth->h_source[3] = 0x9;
	eth->h_source[4] = 0xa;
	eth->h_source[5] = 0xb;
	eth->h_proto = bpf_htons(ETH_P_IP);

	struct iphdr *ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	ip->ihl = 5;
	ip->version = 4;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = bpf_htonl(saddr);
	ip->daddr = bpf_htonl(daddr);
	ip->tos = 4 << 2;

	struct tcphdr *tcp = data + ETH_HLEN + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	tcp->source = bpf_htons(sport);
	tcp->dest = bpf_htons(dport);
	tcp->syn = syn;
	tcp->ack = ack;
	tcp->psh = psh;

	return TC_ACT_OK;
}

static __always_inline int
set_ipv4_tcp(struct __sk_buff *skb,
	     __u32 saddr, __u32 daddr,
	     __u16 sport, __u16 dport)
{
	return set_ipv4_tcp_with_flags(skb, saddr, daddr, sport, dport,
				       true, false, false);
}

static __always_inline int
set_ipv4_tcp_with_dscp(struct __sk_buff *skb,
		       __u32 saddr, __u32 daddr,
		       __u16 sport, __u16 dport,
		       __u8 dscp)
{
	if (set_ipv4_tcp(skb, saddr, daddr, sport, dport))
		return TC_ACT_SHOT;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *ip = data + ETH_HLEN;

	if ((void *)(ip + 1) > data_end)
		return TC_ACT_SHOT;

	ip->tos = dscp << 2;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv4_tcp_fastpath_with_dscp(struct __sk_buff *skb,
			       __u32 saddr, __u32 daddr,
			       __u16 sport, __u16 dport,
			       __u8 dscp)
{
	if (set_ipv4_tcp_with_dscp(skb, saddr, daddr, sport, dport, dscp))
		return TC_ACT_SHOT;
	if (bpf_skb_change_tail(skb, FAST_PATH_PACKET_SIZE, 0))
		return TC_ACT_SHOT;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *ip = data + ETH_HLEN;
	struct tcphdr *tcp = data + ETH_HLEN + IP4_HLEN;

	if (data + FAST_PATH_PACKET_SIZE > data_end ||
	    (void *)(tcp + 1) > data_end)
		return TC_ACT_SHOT;

	ip->tot_len = bpf_htons(FAST_PATH_PACKET_SIZE - ETH_HLEN);
	tcp->doff = 5;
	return TC_ACT_OK;
}

static __always_inline void
set_ipv6_header_dscp(struct ipv6hdr *ip6, __u8 dscp)
{
	__u8 tc = dscp << 2;
	__u8 *raw = (__u8 *)ip6;

	raw[0] = (6 << 4) | (tc >> 4);
	raw[1] = (tc & 0x0f) << 4;
}

static __always_inline int
set_ipv6_tcp_with_dscp(struct __sk_buff *skb,
		       __u32 saddr0, __u32 saddr1, __u32 saddr2, __u32 saddr3,
		       __u32 daddr0, __u32 daddr1, __u32 daddr2, __u32 daddr3,
		       __u16 sport, __u16 dport,
		       __u8 dscp)
{
	if (bpf_skb_change_tail(skb, ETH_HLEN + IP6_HLEN + TCP_HLEN, 0))
		return TC_ACT_SHOT;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + ETH_HLEN + IP6_HLEN + TCP_HLEN > data_end)
		return TC_ACT_SHOT;

	struct ethhdr *eth = data;
	eth->h_dest[0] = 0x0;
	eth->h_dest[1] = 0x1;
	eth->h_dest[2] = 0x2;
	eth->h_dest[3] = 0x3;
	eth->h_dest[4] = 0x4;
	eth->h_dest[5] = 0x5;
	eth->h_source[0] = 0x6;
	eth->h_source[1] = 0x7;
	eth->h_source[2] = 0x8;
	eth->h_source[3] = 0x9;
	eth->h_source[4] = 0xa;
	eth->h_source[5] = 0xb;
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	struct ipv6hdr *ip6 = data + ETH_HLEN;
	set_ipv6_header_dscp(ip6, dscp);
	ip6->payload_len = bpf_htons(TCP_HLEN);
	ip6->nexthdr = IPPROTO_TCP;
	ip6->hop_limit = 64;
	ip6->saddr.in6_u.u6_addr32[0] = bpf_htonl(saddr0);
	ip6->saddr.in6_u.u6_addr32[1] = bpf_htonl(saddr1);
	ip6->saddr.in6_u.u6_addr32[2] = bpf_htonl(saddr2);
	ip6->saddr.in6_u.u6_addr32[3] = bpf_htonl(saddr3);
	ip6->daddr.in6_u.u6_addr32[0] = bpf_htonl(daddr0);
	ip6->daddr.in6_u.u6_addr32[1] = bpf_htonl(daddr1);
	ip6->daddr.in6_u.u6_addr32[2] = bpf_htonl(daddr2);
	ip6->daddr.in6_u.u6_addr32[3] = bpf_htonl(daddr3);

	struct tcphdr *tcp = data + ETH_HLEN + IP6_HLEN;
	tcp->source = bpf_htons(sport);
	tcp->dest = bpf_htons(dport);
	tcp->doff = 5;
	tcp->syn = 1;

	return TC_ACT_OK;
}

static __always_inline int
set_ipv6_tcp_fastpath_with_dscp(struct __sk_buff *skb,
			       __u32 saddr0, __u32 saddr1, __u32 saddr2, __u32 saddr3,
			       __u32 daddr0, __u32 daddr1, __u32 daddr2, __u32 daddr3,
			       __u16 sport, __u16 dport,
			       __u8 dscp)
{
	if (set_ipv6_tcp_with_dscp(skb,
				       saddr0, saddr1, saddr2, saddr3,
				       daddr0, daddr1, daddr2, daddr3,
				       sport, dport, dscp))
		return TC_ACT_SHOT;
	if (bpf_skb_change_tail(skb, FAST_PATH_PACKET_SIZE, 0))
		return TC_ACT_SHOT;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	struct tcphdr *tcp = data + ETH_HLEN + IP6_HLEN;

	if (data + FAST_PATH_PACKET_SIZE > data_end ||
	    (void *)(tcp + 1) > data_end)
		return TC_ACT_SHOT;

	ip6->payload_len = bpf_htons(FAST_PATH_PACKET_SIZE - ETH_HLEN - IP6_HLEN);
	tcp->doff = 5;
	return TC_ACT_OK;
}

static __always_inline int
check_status_and_mark(struct __sk_buff *skb,
		      __u32 expected_status_code,
		      __u32 expected_mark)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != expected_status_code) {
		bpf_printk("status_code(%d) != %d\n", *status_code,
			   expected_status_code);
		return TC_ACT_SHOT;
	}

	if (skb->mark != expected_mark) {
		bpf_printk("skb->mark(%d) != %d\n", skb->mark, expected_mark);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

static __always_inline int
check_redirect_non_syn_tcp(struct __sk_buff *skb)
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

	if (skb->cb[1] != 0) {
		bpf_printk("skb->cb[1] != 0 for non-syn tcp\n");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

static __always_inline int
check_redirect_with_listener_l4proto(struct __sk_buff *skb,
				     __u8 expected_listener_l4proto)
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

	if (skb->cb[1] != expected_listener_l4proto) {
		bpf_printk("skb->cb[1](%d) != %d\n", skb->cb[1],
			   expected_listener_l4proto);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

static __always_inline int
check_redirect_with_listener_l4proto_and_track_ipv4(struct __sk_buff *skb,
						    __u8 expected_listener_l4proto,
						    __u8 expected_from_wan)
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

	if (skb->cb[1] != expected_listener_l4proto) {
		bpf_printk("skb->cb[1](%d) != %d\n", skb->cb[1],
			   expected_listener_l4proto);
		return TC_ACT_SHOT;
	}

	struct ethhdr *eth = data + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_printk("eth->h_proto != ETH_P_IP\n");
		return TC_ACT_SHOT;
	}

	struct iphdr *ip = (void *)eth + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}

	struct redirect_tuple tuple = {};
	tuple.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	tuple.sip.u6_addr32[3] = ip->saddr;
	tuple.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	tuple.dip.u6_addr32[3] = ip->daddr;

	struct redirect_entry *entry =
		bpf_map_lookup_elem(&redirect_track, &tuple);
	if (!entry) {
		bpf_printk("redirect_track entry missing\n");
		return TC_ACT_SHOT;
	}
	if (entry->from_wan != expected_from_wan) {
		bpf_printk("entry->from_wan(%d) != %d\n", entry->from_wan,
			   expected_from_wan);
		return TC_ACT_SHOT;
	}
	if (entry->last_seen_ns == 0) {
		bpf_printk("entry->last_seen_ns == 0\n");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

static __always_inline int
check_tcp_conn_state_ipv4_tcp(struct __sk_buff *skb,
			      __u32 expected_status_code,
			      __u32 saddr, __u32 daddr,
			      __u16 sport, __u16 dport,
			      __u8 expected_outbound,
			      __u32 expected_mark,
			      bool expect_eth)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != expected_status_code) {
		bpf_printk("status_code(%d) != %d\n", *status_code, expected_status_code);
		return TC_ACT_SHOT;
	}

	struct iphdr *ip;

	if (expect_eth) {
		struct ethhdr *eth = data + sizeof(*status_code);
		if ((void *)(eth + 1) > data_end) {
			bpf_printk("data + sizeof(*eth) > data_end\n");
			return TC_ACT_SHOT;
		}
		if (eth->h_proto != bpf_htons(ETH_P_IP)) {
			bpf_printk("eth->h_proto != ETH_P_IP\n");
			return TC_ACT_SHOT;
		}
		ip = (void *)eth + ETH_HLEN;
	} else {
		ip = data + sizeof(*status_code);
	}

	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip->protocol != IPPROTO_TCP) {
		bpf_printk("ip->protocol != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}

	struct tcphdr *tcp = (void *)ip + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
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

	struct conn_state *conn_state;
	conn_state = bpf_map_lookup_elem(&conn_state_map, &tuples.five);
	if (!conn_state) {
		bpf_printk("conn_state == NULL\n");
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.has_routing == 0) {
		bpf_printk("conn_state->meta.data.has_routing == 0\n");
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.outbound != expected_outbound) {
		bpf_printk("conn_state->meta.data.outbound(%d) != %d\n",
			   conn_state->meta.data.outbound, expected_outbound);
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.mark != expected_mark) {
		bpf_printk("conn_state->meta.data.mark(%d) != %d\n",
			   conn_state->meta.data.mark, expected_mark);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

static __always_inline int
check_tcp_conn_state_ipv4_tcp_dscp(struct __sk_buff *skb,
				   __u32 expected_status_code,
				   __u32 saddr, __u32 daddr,
				   __u16 sport, __u16 dport,
				   __u8 expected_outbound,
				   __u32 expected_mark,
				   __u8 expected_dscp,
				   bool expect_eth)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != expected_status_code) {
		bpf_printk("status_code(%d) != %d\n", *status_code, expected_status_code);
		return TC_ACT_SHOT;
	}

	struct iphdr *ip;

	if (expect_eth) {
		struct ethhdr *eth = data + sizeof(*status_code);
		if ((void *)(eth + 1) > data_end) {
			bpf_printk("data + sizeof(*eth) > data_end\n");
			return TC_ACT_SHOT;
		}
		if (eth->h_proto != bpf_htons(ETH_P_IP)) {
			bpf_printk("eth->h_proto != ETH_P_IP\n");
			return TC_ACT_SHOT;
		}
		ip = (void *)eth + ETH_HLEN;
	} else {
		ip = data + sizeof(*status_code);
	}

	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip->protocol != IPPROTO_TCP) {
		bpf_printk("ip->protocol != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}

	struct tcphdr *tcp = (void *)ip + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
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

	struct conn_state *conn_state;
	conn_state = bpf_map_lookup_elem(&conn_state_map, &tuples.five);
	if (!conn_state) {
		bpf_printk("conn_state == NULL\n");
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.has_routing == 0) {
		bpf_printk("conn_state->meta.data.has_routing == 0\n");
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.outbound != expected_outbound) {
		bpf_printk("conn_state->meta.data.outbound(%d) != %d\n",
			   conn_state->meta.data.outbound, expected_outbound);
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.mark != expected_mark) {
		bpf_printk("conn_state->meta.data.mark(%d) != %d\n",
			   conn_state->meta.data.mark, expected_mark);
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.dscp != expected_dscp) {
		bpf_printk("conn_state->meta.data.dscp(%d) != %d\n",
			   conn_state->meta.data.dscp, expected_dscp);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

static __always_inline int
check_tcp_conn_state_ipv6_tcp_dscp(struct __sk_buff *skb,
				   __u32 expected_status_code,
				   __u32 saddr0, __u32 saddr1, __u32 saddr2, __u32 saddr3,
				   __u32 daddr0, __u32 daddr1, __u32 daddr2, __u32 daddr3,
				   __u16 sport, __u16 dport,
				   __u8 expected_outbound,
				   __u32 expected_mark,
				   __u8 expected_dscp,
				   bool expect_eth)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != expected_status_code) {
		bpf_printk("status_code(%d) != %d\n", *status_code, expected_status_code);
		return TC_ACT_SHOT;
	}

	struct ipv6hdr *ip6;

	if (expect_eth) {
		struct ethhdr *eth = data + sizeof(*status_code);
		if ((void *)(eth + 1) > data_end) {
			bpf_printk("data + sizeof(*eth) > data_end\n");
			return TC_ACT_SHOT;
		}
		if (eth->h_proto != bpf_htons(ETH_P_IPV6)) {
			bpf_printk("eth->h_proto != ETH_P_IPV6\n");
			return TC_ACT_SHOT;
		}
		ip6 = (void *)eth + ETH_HLEN;
	} else {
		ip6 = data + sizeof(*status_code);
	}

	if ((void *)(ip6 + 1) > data_end) {
		bpf_printk("data + sizeof(*ip6) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip6->nexthdr != IPPROTO_TCP) {
		bpf_printk("ip6->nexthdr != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}

	struct tcphdr *tcp = (void *)ip6 + IP6_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}

	if (ip6->saddr.in6_u.u6_addr32[0] != bpf_htonl(saddr0) ||
	    ip6->saddr.in6_u.u6_addr32[1] != bpf_htonl(saddr1) ||
	    ip6->saddr.in6_u.u6_addr32[2] != bpf_htonl(saddr2) ||
	    ip6->saddr.in6_u.u6_addr32[3] != bpf_htonl(saddr3)) {
		bpf_printk("ip6->saddr mismatch\n");
		return TC_ACT_SHOT;
	}
	if (ip6->daddr.in6_u.u6_addr32[0] != bpf_htonl(daddr0) ||
	    ip6->daddr.in6_u.u6_addr32[1] != bpf_htonl(daddr1) ||
	    ip6->daddr.in6_u.u6_addr32[2] != bpf_htonl(daddr2) ||
	    ip6->daddr.in6_u.u6_addr32[3] != bpf_htonl(daddr3)) {
		bpf_printk("ip6->daddr mismatch\n");
		return TC_ACT_SHOT;
	}

	struct tuples tuples = {};
	__builtin_memcpy(&tuples.five.sip, &ip6->saddr, sizeof(ip6->saddr));
	__builtin_memcpy(&tuples.five.dip, &ip6->daddr, sizeof(ip6->daddr));
	tuples.five.sport = tcp->source;
	tuples.five.dport = tcp->dest;
	tuples.five.l4proto = ip6->nexthdr;

	struct conn_state *conn_state;
	conn_state = bpf_map_lookup_elem(&conn_state_map, &tuples.five);
	if (!conn_state) {
		bpf_printk("conn_state == NULL\n");
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.has_routing == 0) {
		bpf_printk("conn_state->meta.data.has_routing == 0\n");
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.outbound != expected_outbound) {
		bpf_printk("conn_state->meta.data.outbound(%d) != %d\n",
			   conn_state->meta.data.outbound, expected_outbound);
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.mark != expected_mark) {
		bpf_printk("conn_state->meta.data.mark(%d) != %d\n",
			   conn_state->meta.data.mark, expected_mark);
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.dscp != expected_dscp) {
		bpf_printk("conn_state->meta.data.dscp(%d) != %d\n",
			   conn_state->meta.data.dscp, expected_dscp);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

static __always_inline int
check_routing_ipv4_tcp_state(struct __sk_buff *skb,
			     __u32 expected_status_code,
			     __u32 saddr, __u32 daddr,
			     __u16 sport, __u16 dport,
			     __u8 expected_outbound,
			     __u32 expected_mark,
			     bool expect_eth)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != expected_status_code) {
		bpf_printk("status_code(%d) != %d\n", *status_code, expected_status_code);
		return TC_ACT_SHOT;
	}

	if (expected_status_code == TC_ACT_REDIRECT) {
		if (skb->cb[0] != TPROXY_MARK) {
			bpf_printk("skb->cb[0] != TPROXY_MARK\n");
			return TC_ACT_SHOT;
		}

		if (skb->cb[1] != IPPROTO_TCP) {
			bpf_printk("skb->cb[1] != IPPROTO_TCP\n");
			return TC_ACT_SHOT;
		}

	}

	struct iphdr *ip;

	if (expect_eth) {
		struct ethhdr *eth = data + sizeof(*status_code);
		if ((void *)(eth + 1) > data_end) {
			bpf_printk("data + sizeof(*eth) > data_end\n");
			return TC_ACT_SHOT;
		}
		if (eth->h_proto != bpf_htons(ETH_P_IP)) {
			bpf_printk("eth->h_proto != ETH_P_IP\n");
			return TC_ACT_SHOT;
		}
		ip = (void *)eth + ETH_HLEN;
	} else {
		ip = data + sizeof(*status_code);
	}

	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip->protocol != IPPROTO_TCP) {
		bpf_printk("ip->protocol != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}
	if (ip->saddr != bpf_htonl(saddr)) {
		bpf_printk("ip->saddr != %pI4\n", &saddr);
		return TC_ACT_SHOT;
	}
	if (ip->daddr != bpf_htonl(daddr)) {
		bpf_printk("ip->daddr != %pI4\n", &daddr);
		return TC_ACT_SHOT;
	}

	struct tcphdr *tcp = (void *)ip + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (tcp->source != bpf_htons(sport)) {
		bpf_printk("tcp->source != %d\n", sport);
		return TC_ACT_SHOT;
	}
	if (tcp->dest != bpf_htons(dport)) {
		bpf_printk("tcp->dest != %d\n", dport);
		return TC_ACT_SHOT;
	}

	if (expected_status_code == TC_ACT_REDIRECT) {
		struct tuples tuples = {};
		tuples.five.sip.u6_addr32[2] = bpf_htonl(0xffff);
		tuples.five.sip.u6_addr32[3] = ip->saddr;
		tuples.five.dip.u6_addr32[2] = bpf_htonl(0xffff);
		tuples.five.dip.u6_addr32[3] = ip->daddr;
		tuples.five.sport = tcp->source;
		tuples.five.dport = tcp->dest;
		tuples.five.l4proto = ip->protocol;

		// Scheme3: Read routing result from conn_state_map instead of routing_tuples_map
		struct conn_state *conn_state;
		conn_state = bpf_map_lookup_elem(&conn_state_map, &tuples.five);
		if (!conn_state) {
			bpf_printk("conn_state == NULL\n");
			return TC_ACT_SHOT;
		}

		if (conn_state->meta.data.has_routing == 0) {
			bpf_printk("conn_state->meta.data.has_routing == 0\n");
			return TC_ACT_SHOT;
		}

		if (conn_state->meta.data.outbound != expected_outbound) {
			bpf_printk("conn_state->meta.data.outbound(%d) != %d\n",
				   conn_state->meta.data.outbound, expected_outbound);
			return TC_ACT_SHOT;
		}

		if (conn_state->meta.data.mark != expected_mark) {
			bpf_printk("conn_state->meta.data.mark(%d) != %d\n",
				   conn_state->meta.data.mark, expected_mark);
			return TC_ACT_SHOT;
		}
	}

	return TC_ACT_OK;
}

static __always_inline int
check_udp_conn_state_ipv4_udp_dscp(struct __sk_buff *skb,
				   __u32 expected_status_code,
				   __u32 saddr, __u32 daddr,
				   __u16 sport, __u16 dport,
				   __u8 expected_outbound,
				   __u32 expected_mark,
				   __u8 expected_dscp,
				   bool expect_eth)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != expected_status_code) {
		bpf_printk("status_code(%d) != %d\n", *status_code, expected_status_code);
		return TC_ACT_SHOT;
	}

	struct iphdr *ip;

	if (expect_eth) {
		struct ethhdr *eth = data + sizeof(*status_code);
		if ((void *)(eth + 1) > data_end) {
			bpf_printk("data + sizeof(*eth) > data_end\n");
			return TC_ACT_SHOT;
		}
		if (eth->h_proto != bpf_htons(ETH_P_IP)) {
			bpf_printk("eth->h_proto != ETH_P_IP\n");
			return TC_ACT_SHOT;
		}
		ip = (void *)eth + ETH_HLEN;
	} else {
		ip = data + sizeof(*status_code);
	}

	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip->protocol != IPPROTO_UDP) {
		bpf_printk("ip->protocol != IPPROTO_UDP\n");
		return TC_ACT_SHOT;
	}

	struct udphdr *udp = (void *)ip + IP4_HLEN;
	if ((void *)(udp + 1) > data_end) {
		bpf_printk("data + sizeof(*udp) > data_end\n");
		return TC_ACT_SHOT;
	}

	struct tuples tuples = {};
	tuples.five.sip.u6_addr32[2] = bpf_htonl(0xffff);
	tuples.five.sip.u6_addr32[3] = ip->saddr;
	tuples.five.dip.u6_addr32[2] = bpf_htonl(0xffff);
	tuples.five.dip.u6_addr32[3] = ip->daddr;
	tuples.five.sport = udp->source;
	tuples.five.dport = udp->dest;
	tuples.five.l4proto = ip->protocol;

	struct conn_state *conn_state;
	conn_state = bpf_map_lookup_elem(&conn_state_map, &tuples.five);
	if (!conn_state) {
		bpf_printk("conn_state == NULL\n");
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.has_routing == 0) {
		bpf_printk("conn_state->meta.data.has_routing == 0\n");
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.outbound != expected_outbound) {
		bpf_printk("conn_state->meta.data.outbound(%d) != %d\n",
			   conn_state->meta.data.outbound, expected_outbound);
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.mark != expected_mark) {
		bpf_printk("conn_state->meta.data.mark(%d) != %d\n",
			   conn_state->meta.data.mark, expected_mark);
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.dscp != expected_dscp) {
		bpf_printk("conn_state->meta.data.dscp(%d) != %d\n",
			   conn_state->meta.data.dscp, expected_dscp);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

static __always_inline int
check_routing_ipv6_tcp_state(struct __sk_buff *skb,
			     __u32 expected_status_code,
			     __u32 saddr0, __u32 saddr1, __u32 saddr2, __u32 saddr3,
			     __u32 daddr0, __u32 daddr1, __u32 daddr2, __u32 daddr3,
			     __u16 sport, __u16 dport,
			     __u8 expected_outbound,
			     __u32 expected_mark,
			     bool expect_eth)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != expected_status_code) {
		bpf_printk("status_code(%d) != %d\n", *status_code, expected_status_code);
		return TC_ACT_SHOT;
	}

	if (expected_status_code == TC_ACT_REDIRECT) {
		if (skb->cb[0] != TPROXY_MARK) {
			bpf_printk("skb->cb[0] != TPROXY_MARK\n");
			return TC_ACT_SHOT;
		}
		if (skb->cb[1] != IPPROTO_TCP) {
			bpf_printk("skb->cb[1] != IPPROTO_TCP\n");
			return TC_ACT_SHOT;
		}
	}

	struct ipv6hdr *ip6;

	if (expect_eth) {
		struct ethhdr *eth = data + sizeof(*status_code);
		if ((void *)(eth + 1) > data_end) {
			bpf_printk("data + sizeof(*eth) > data_end\n");
			return TC_ACT_SHOT;
		}
		if (eth->h_proto != bpf_htons(ETH_P_IPV6)) {
			bpf_printk("eth->h_proto != ETH_P_IPV6\n");
			return TC_ACT_SHOT;
		}
		ip6 = (void *)eth + ETH_HLEN;
	} else {
		ip6 = data + sizeof(*status_code);
	}

	if ((void *)(ip6 + 1) > data_end) {
		bpf_printk("data + sizeof(*ip6) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip6->nexthdr != IPPROTO_TCP) {
		bpf_printk("ip6->nexthdr != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}

	struct tcphdr *tcp = (void *)ip6 + IP6_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (tcp->source != bpf_htons(sport)) {
		bpf_printk("tcp->source != %d\n", sport);
		return TC_ACT_SHOT;
	}
	if (tcp->dest != bpf_htons(dport)) {
		bpf_printk("tcp->dest != %d\n", dport);
		return TC_ACT_SHOT;
	}

	if (ip6->saddr.in6_u.u6_addr32[0] != bpf_htonl(saddr0) ||
	    ip6->saddr.in6_u.u6_addr32[1] != bpf_htonl(saddr1) ||
	    ip6->saddr.in6_u.u6_addr32[2] != bpf_htonl(saddr2) ||
	    ip6->saddr.in6_u.u6_addr32[3] != bpf_htonl(saddr3)) {
		bpf_printk("ip6->saddr mismatch\n");
		return TC_ACT_SHOT;
	}
	if (ip6->daddr.in6_u.u6_addr32[0] != bpf_htonl(daddr0) ||
	    ip6->daddr.in6_u.u6_addr32[1] != bpf_htonl(daddr1) ||
	    ip6->daddr.in6_u.u6_addr32[2] != bpf_htonl(daddr2) ||
	    ip6->daddr.in6_u.u6_addr32[3] != bpf_htonl(daddr3)) {
		bpf_printk("ip6->daddr mismatch\n");
		return TC_ACT_SHOT;
	}

	if (expected_status_code == TC_ACT_REDIRECT) {
		struct tuples tuples = {};
		__builtin_memcpy(&tuples.five.sip, &ip6->saddr, sizeof(ip6->saddr));
		__builtin_memcpy(&tuples.five.dip, &ip6->daddr, sizeof(ip6->daddr));
		tuples.five.sport = tcp->source;
		tuples.five.dport = tcp->dest;
		tuples.five.l4proto = ip6->nexthdr;

		struct conn_state *conn_state;
		conn_state = bpf_map_lookup_elem(&conn_state_map, &tuples.five);
		if (!conn_state) {
			bpf_printk("conn_state == NULL\n");
			return TC_ACT_SHOT;
		}

		if (conn_state->meta.data.has_routing == 0) {
			bpf_printk("conn_state->meta.data.has_routing == 0\n");
			return TC_ACT_SHOT;
		}

		if (conn_state->meta.data.outbound != expected_outbound) {
			bpf_printk("conn_state->meta.data.outbound(%d) != %d\n",
				   conn_state->meta.data.outbound, expected_outbound);
			return TC_ACT_SHOT;
		}

		if (conn_state->meta.data.mark != expected_mark) {
			bpf_printk("conn_state->meta.data.mark(%d) != %d\n",
				   conn_state->meta.data.mark, expected_mark);
			return TC_ACT_SHOT;
		}
	}

	return TC_ACT_OK;
}

static __always_inline int
check_routing_ipv6_tcp(struct __sk_buff *skb,
		       __u32 expected_status_code,
		       __u32 saddr0, __u32 saddr1, __u32 saddr2, __u32 saddr3,
		       __u32 daddr0, __u32 daddr1, __u32 daddr2, __u32 daddr3,
		       __u16 sport, __u16 dport)
{
	return check_routing_ipv6_tcp_state(skb,
					    expected_status_code,
					    saddr0, saddr1, saddr2, saddr3,
					    daddr0, daddr1, daddr2, daddr3,
					    sport, dport,
					    OUTBOUND_USER_DEFINED_MIN,
					    0,
					    true);
}

static __always_inline int
check_routing_ipv4_tcp(struct __sk_buff *skb,
		       __u32 expected_status_code,
		       __u32 saddr, __u32 daddr,
		       __u16 sport, __u16 dport)
{
	return check_routing_ipv4_tcp_state(skb,
					    expected_status_code,
					    saddr, daddr,
					    sport, dport,
					    OUTBOUND_USER_DEFINED_MIN,
					    0,
					    true);
}

static __always_inline void
set_routing_fallback(__u8 outbound, bool must)
{
	struct match_set ms = {};
	ms.not = false;
	ms.type = MatchType_Fallback;
	ms.outbound = outbound;
	ms.must = must;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &one_key, &ms, BPF_ANY);
}

// BUG-002 test helper: Create a minimal IPv4 UDP packet (42 bytes total)
// This is the smallest valid UDP packet, used to test the bug where
// parse_transport_fast incorrectly uses sizeof(struct tcphdr) for boundary check.
static __always_inline int
set_minimal_ipv4_udp(struct __sk_buff *skb,
		     __u32 saddr, __u32 daddr,
		     __u16 sport, __u16 dport)
{
#define MIN_UDP_PACKET_SIZE 42  // 14 (ETH) + 20 (IP) + 8 (UDP)

	if (bpf_skb_change_tail(skb, MIN_UDP_PACKET_SIZE, 0))
		return TC_ACT_SHOT;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	// Verify full packet size is available
	if (data + MIN_UDP_PACKET_SIZE > data_end)
		return TC_ACT_SHOT;

	struct ethhdr *eth = data;
	eth->h_dest[0] = 0x0;
	eth->h_dest[1] = 0x1;
	eth->h_dest[2] = 0x2;
	eth->h_dest[3] = 0x3;
	eth->h_dest[4] = 0x4;
	eth->h_dest[5] = 0x5;
	eth->h_source[0] = 0x6;
	eth->h_source[1] = 0x7;
	eth->h_source[2] = 0x8;
	eth->h_source[3] = 0x9;
	eth->h_source[4] = 0xa;
	eth->h_source[5] = 0xb;
	eth->h_proto = bpf_htons(ETH_P_IP);

	struct iphdr *ip = data + ETH_HLEN;
	ip->ihl = 5;
	ip->version = 4;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = bpf_htonl(saddr);
	ip->daddr = bpf_htonl(daddr);
	ip->tos = 0;
	ip->tot_len = bpf_htons(20 + 8);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->check = 0;

	struct udphdr *udp = data + ETH_HLEN + IP4_HLEN;
	udp->source = bpf_htons(sport);
	udp->dest = bpf_htons(dport);
	udp->len = bpf_htons(8);
	udp->check = 0;

	return TC_ACT_OK;
}

static __always_inline int
set_minimal_ipv4_udp_with_dscp(struct __sk_buff *skb,
			       __u32 saddr, __u32 daddr,
			       __u16 sport, __u16 dport,
			       __u8 dscp)
{
	if (set_minimal_ipv4_udp(skb, saddr, daddr, sport, dport))
		return TC_ACT_SHOT;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *ip = data + ETH_HLEN;

	if ((void *)(ip + 1) > data_end)
		return TC_ACT_SHOT;

	ip->tos = dscp << 2;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv4_udp_fastpath_with_dscp(struct __sk_buff *skb,
			       __u32 saddr, __u32 daddr,
			       __u16 sport, __u16 dport,
			       __u8 dscp)
{
	if (set_minimal_ipv4_udp_with_dscp(skb, saddr, daddr, sport, dport, dscp))
		return TC_ACT_SHOT;
	if (bpf_skb_change_tail(skb, FAST_PATH_PACKET_SIZE, 0))
		return TC_ACT_SHOT;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *ip = data + ETH_HLEN;
	struct udphdr *udp = data + ETH_HLEN + IP4_HLEN;

	if (data + FAST_PATH_PACKET_SIZE > data_end ||
	    (void *)(udp + 1) > data_end)
		return TC_ACT_SHOT;

	ip->tot_len = bpf_htons(FAST_PATH_PACKET_SIZE - ETH_HLEN);
	udp->len = bpf_htons(FAST_PATH_PACKET_SIZE - ETH_HLEN - IP4_HLEN);
	return TC_ACT_OK;
}

static __always_inline int
set_minimal_ipv6_udp_with_dscp(struct __sk_buff *skb,
			       __u32 saddr0, __u32 saddr1, __u32 saddr2, __u32 saddr3,
			       __u32 daddr0, __u32 daddr1, __u32 daddr2, __u32 daddr3,
			       __u16 sport, __u16 dport,
			       __u8 dscp)
{
	if (bpf_skb_change_tail(skb, ETH_HLEN + IP6_HLEN + sizeof(struct udphdr), 0))
		return TC_ACT_SHOT;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + ETH_HLEN + IP6_HLEN + sizeof(struct udphdr) > data_end)
		return TC_ACT_SHOT;

	struct ethhdr *eth = data;
	eth->h_dest[0] = 0x0;
	eth->h_dest[1] = 0x1;
	eth->h_dest[2] = 0x2;
	eth->h_dest[3] = 0x3;
	eth->h_dest[4] = 0x4;
	eth->h_dest[5] = 0x5;
	eth->h_source[0] = 0x6;
	eth->h_source[1] = 0x7;
	eth->h_source[2] = 0x8;
	eth->h_source[3] = 0x9;
	eth->h_source[4] = 0xa;
	eth->h_source[5] = 0xb;
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	struct ipv6hdr *ip6 = data + ETH_HLEN;
	set_ipv6_header_dscp(ip6, dscp);
	ip6->payload_len = bpf_htons(sizeof(struct udphdr));
	ip6->nexthdr = IPPROTO_UDP;
	ip6->hop_limit = 64;
	ip6->saddr.in6_u.u6_addr32[0] = bpf_htonl(saddr0);
	ip6->saddr.in6_u.u6_addr32[1] = bpf_htonl(saddr1);
	ip6->saddr.in6_u.u6_addr32[2] = bpf_htonl(saddr2);
	ip6->saddr.in6_u.u6_addr32[3] = bpf_htonl(saddr3);
	ip6->daddr.in6_u.u6_addr32[0] = bpf_htonl(daddr0);
	ip6->daddr.in6_u.u6_addr32[1] = bpf_htonl(daddr1);
	ip6->daddr.in6_u.u6_addr32[2] = bpf_htonl(daddr2);
	ip6->daddr.in6_u.u6_addr32[3] = bpf_htonl(daddr3);

	struct udphdr *udp = data + ETH_HLEN + IP6_HLEN;
	udp->source = bpf_htons(sport);
	udp->dest = bpf_htons(dport);
	udp->len = bpf_htons(sizeof(struct udphdr));
	udp->check = 0;

	return TC_ACT_OK;
}

static __always_inline int
set_ipv6_udp_fastpath_with_dscp(struct __sk_buff *skb,
			       __u32 saddr0, __u32 saddr1, __u32 saddr2, __u32 saddr3,
			       __u32 daddr0, __u32 daddr1, __u32 daddr2, __u32 daddr3,
			       __u16 sport, __u16 dport,
			       __u8 dscp)
{
	if (set_minimal_ipv6_udp_with_dscp(skb,
				       saddr0, saddr1, saddr2, saddr3,
				       daddr0, daddr1, daddr2, daddr3,
				       sport, dport, dscp))
		return TC_ACT_SHOT;
	if (bpf_skb_change_tail(skb, FAST_PATH_PACKET_SIZE, 0))
		return TC_ACT_SHOT;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	struct udphdr *udp = data + ETH_HLEN + IP6_HLEN;

	if (data + FAST_PATH_PACKET_SIZE > data_end ||
	    (void *)(udp + 1) > data_end)
		return TC_ACT_SHOT;

	ip6->payload_len = bpf_htons(FAST_PATH_PACKET_SIZE - ETH_HLEN - IP6_HLEN);
	udp->len = bpf_htons(FAST_PATH_PACKET_SIZE - ETH_HLEN - IP6_HLEN);
	return TC_ACT_OK;
}

static __always_inline int
check_udp_conn_state_ipv6_udp_dscp(struct __sk_buff *skb,
				   __u32 expected_status_code,
				   __u32 saddr0, __u32 saddr1, __u32 saddr2, __u32 saddr3,
				   __u32 daddr0, __u32 daddr1, __u32 daddr2, __u32 daddr3,
				   __u16 sport, __u16 dport,
				   __u8 expected_outbound,
				   __u32 expected_mark,
				   __u8 expected_dscp,
				   bool expect_eth)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != expected_status_code) {
		bpf_printk("status_code(%d) != %d\n", *status_code, expected_status_code);
		return TC_ACT_SHOT;
	}

	struct ipv6hdr *ip6;

	if (expect_eth) {
		struct ethhdr *eth = data + sizeof(*status_code);
		if ((void *)(eth + 1) > data_end) {
			bpf_printk("data + sizeof(*eth) > data_end\n");
			return TC_ACT_SHOT;
		}
		if (eth->h_proto != bpf_htons(ETH_P_IPV6)) {
			bpf_printk("eth->h_proto != ETH_P_IPV6\n");
			return TC_ACT_SHOT;
		}
		ip6 = (void *)eth + ETH_HLEN;
	} else {
		ip6 = data + sizeof(*status_code);
	}

	if ((void *)(ip6 + 1) > data_end) {
		bpf_printk("data + sizeof(*ip6) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip6->nexthdr != IPPROTO_UDP) {
		bpf_printk("ip6->nexthdr != IPPROTO_UDP\n");
		return TC_ACT_SHOT;
	}

	struct udphdr *udp = (void *)ip6 + IP6_HLEN;
	if ((void *)(udp + 1) > data_end) {
		bpf_printk("data + sizeof(*udp) > data_end\n");
		return TC_ACT_SHOT;
	}

	if (ip6->saddr.in6_u.u6_addr32[0] != bpf_htonl(saddr0) ||
	    ip6->saddr.in6_u.u6_addr32[1] != bpf_htonl(saddr1) ||
	    ip6->saddr.in6_u.u6_addr32[2] != bpf_htonl(saddr2) ||
	    ip6->saddr.in6_u.u6_addr32[3] != bpf_htonl(saddr3)) {
		bpf_printk("ip6->saddr mismatch\n");
		return TC_ACT_SHOT;
	}
	if (ip6->daddr.in6_u.u6_addr32[0] != bpf_htonl(daddr0) ||
	    ip6->daddr.in6_u.u6_addr32[1] != bpf_htonl(daddr1) ||
	    ip6->daddr.in6_u.u6_addr32[2] != bpf_htonl(daddr2) ||
	    ip6->daddr.in6_u.u6_addr32[3] != bpf_htonl(daddr3)) {
		bpf_printk("ip6->daddr mismatch\n");
		return TC_ACT_SHOT;
	}

	struct tuples tuples = {};
	__builtin_memcpy(&tuples.five.sip, &ip6->saddr, sizeof(ip6->saddr));
	__builtin_memcpy(&tuples.five.dip, &ip6->daddr, sizeof(ip6->daddr));
	tuples.five.sport = udp->source;
	tuples.five.dport = udp->dest;
	tuples.five.l4proto = ip6->nexthdr;

	struct conn_state *conn_state;
	conn_state = bpf_map_lookup_elem(&conn_state_map, &tuples.five);
	if (!conn_state) {
		bpf_printk("conn_state == NULL\n");
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.has_routing == 0) {
		bpf_printk("conn_state->meta.data.has_routing == 0\n");
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.outbound != expected_outbound) {
		bpf_printk("conn_state->meta.data.outbound(%d) != %d\n",
			   conn_state->meta.data.outbound, expected_outbound);
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.mark != expected_mark) {
		bpf_printk("conn_state->meta.data.mark(%d) != %d\n",
			   conn_state->meta.data.mark, expected_mark);
		return TC_ACT_SHOT;
	}

	if (conn_state->meta.data.dscp != expected_dscp) {
		bpf_printk("conn_state->meta.data.dscp(%d) != %d\n",
			   conn_state->meta.data.dscp, expected_dscp);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

static __always_inline int
set_ipv4_udp_first_fragment(struct __sk_buff *skb,
			    __u32 saddr, __u32 daddr,
			    __u16 sport, __u16 dport)
{
	if (bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + sizeof(struct udphdr), 0))
		return TC_ACT_SHOT;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + ETH_HLEN + IP4_HLEN + sizeof(struct udphdr) > data_end)
		return TC_ACT_SHOT;

	struct ethhdr *eth = data;
	eth->h_dest[0] = 0x0;
	eth->h_dest[1] = 0x1;
	eth->h_dest[2] = 0x2;
	eth->h_dest[3] = 0x3;
	eth->h_dest[4] = 0x4;
	eth->h_dest[5] = 0x5;
	eth->h_source[0] = 0x6;
	eth->h_source[1] = 0x7;
	eth->h_source[2] = 0x8;
	eth->h_source[3] = 0x9;
	eth->h_source[4] = 0xa;
	eth->h_source[5] = 0xb;
	eth->h_proto = bpf_htons(ETH_P_IP);

	struct iphdr *ip = data + ETH_HLEN;
	ip->ihl = 5;
	ip->version = 4;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = bpf_htonl(saddr);
	ip->daddr = bpf_htonl(daddr);
	ip->tos = 0;
	ip->tot_len = bpf_htons(IP4_HLEN + sizeof(struct udphdr));
	ip->id = bpf_htons(1);
	ip->frag_off = bpf_htons(IPV4_MF_FLAG);
	ip->ttl = 64;
	ip->check = 0;

	struct udphdr *udp = data + ETH_HLEN + IP4_HLEN;
	udp->source = bpf_htons(sport);
	udp->dest = bpf_htons(dport);
	udp->len = bpf_htons(sizeof(struct udphdr));
	udp->check = 0;

	return TC_ACT_OK;
}

static __always_inline int
set_ipv4_udp_non_initial_fragment(struct __sk_buff *skb,
				  __u32 saddr, __u32 daddr)
{
	const __u32 payload_len = 8;

	if (bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + payload_len, 0))
		return TC_ACT_SHOT;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + ETH_HLEN + IP4_HLEN + payload_len > data_end)
		return TC_ACT_SHOT;

	struct ethhdr *eth = data;
	eth->h_dest[0] = 0x0;
	eth->h_dest[1] = 0x1;
	eth->h_dest[2] = 0x2;
	eth->h_dest[3] = 0x3;
	eth->h_dest[4] = 0x4;
	eth->h_dest[5] = 0x5;
	eth->h_source[0] = 0x6;
	eth->h_source[1] = 0x7;
	eth->h_source[2] = 0x8;
	eth->h_source[3] = 0x9;
	eth->h_source[4] = 0xa;
	eth->h_source[5] = 0xb;
	eth->h_proto = bpf_htons(ETH_P_IP);

	struct iphdr *ip = data + ETH_HLEN;
	ip->ihl = 5;
	ip->version = 4;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = bpf_htonl(saddr);
	ip->daddr = bpf_htonl(daddr);
	ip->tos = 0;
	ip->tot_len = bpf_htons(IP4_HLEN + payload_len);
	ip->id = bpf_htons(1);
	ip->frag_off = bpf_htons(IPV4_MF_FLAG | 1);
	ip->ttl = 64;
	ip->check = 0;

	__builtin_memset(data + ETH_HLEN + IP4_HLEN, 0xab, payload_len);

	return TC_ACT_OK;
}

static __always_inline int
set_ipv4_tcp_first_fragment_with_flags(struct __sk_buff *skb,
				       __u32 saddr, __u32 daddr,
				       __u16 sport, __u16 dport,
				       bool syn, bool ack, bool psh)
{
	if (bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + TCP_HLEN, 0))
		return TC_ACT_SHOT;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + ETH_HLEN + IP4_HLEN + TCP_HLEN > data_end)
		return TC_ACT_SHOT;

	struct ethhdr *eth = data;
	eth->h_dest[0] = 0x0;
	eth->h_dest[1] = 0x1;
	eth->h_dest[2] = 0x2;
	eth->h_dest[3] = 0x3;
	eth->h_dest[4] = 0x4;
	eth->h_dest[5] = 0x5;
	eth->h_source[0] = 0x6;
	eth->h_source[1] = 0x7;
	eth->h_source[2] = 0x8;
	eth->h_source[3] = 0x9;
	eth->h_source[4] = 0xa;
	eth->h_source[5] = 0xb;
	eth->h_proto = bpf_htons(ETH_P_IP);

	struct iphdr *ip = data + ETH_HLEN;
	ip->ihl = 5;
	ip->version = 4;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = bpf_htonl(saddr);
	ip->daddr = bpf_htonl(daddr);
	ip->tos = 4 << 2;
	ip->tot_len = bpf_htons(IP4_HLEN + TCP_HLEN);
	ip->id = bpf_htons(1);
	ip->frag_off = bpf_htons(IPV4_MF_FLAG);
	ip->ttl = 64;
	ip->check = 0;

	struct tcphdr *tcp = data + ETH_HLEN + IP4_HLEN;
	tcp->source = bpf_htons(sport);
	tcp->dest = bpf_htons(dport);
	tcp->doff = 5;
	tcp->syn = syn;
	tcp->ack = ack;
	tcp->psh = psh;

	return TC_ACT_OK;
}

// BUG-001 test helper: Create IPv6 packet with large extension headers
// The extension headers are sized to exceed 512 bytes total after IPv6 base header,
// triggering the bug where parse_transport_fast returns -EFAULT instead of -1.
//
// NOTE: This test uses a fixed 512-byte packet which forces parse_transport_fast
// to hit the boundary check limit. The test verifies that packets at the exact
// boundary are handled correctly (fallback to slow path) rather than rejected.
static __always_inline int
set_ipv6_with_large_extensions(struct __sk_buff *skb,
				__u32 saddr0, __u32 saddr1, __u32 saddr2, __u32 saddr3,
				__u32 daddr0, __u32 daddr1, __u32 daddr2, __u32 daddr3,
				__u16 sport, __u16 dport, __u8 l4proto)
{
	// Use exactly 512 bytes which is the HEADER_PULL_SIZE limit in parse_transport_fast
	// This forces the fast path to handle extension headers at the boundary
#define PACKET_SIZE 512

	if (bpf_skb_change_tail(skb, PACKET_SIZE, 0))
		return TC_ACT_SHOT;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	// Verify we have the full packet size
	if (data + PACKET_SIZE > data_end)
		return TC_ACT_SHOT;

	struct ethhdr *eth = data;
	eth->h_dest[0] = 0x0;
	eth->h_dest[1] = 0x1;
	eth->h_dest[2] = 0x2;
	eth->h_dest[3] = 0x3;
	eth->h_dest[4] = 0x4;
	eth->h_dest[5] = 0x5;
	eth->h_source[0] = 0x6;
	eth->h_source[1] = 0x7;
	eth->h_source[2] = 0x8;
	eth->h_source[3] = 0x9;
	eth->h_source[4] = 0xa;
	eth->h_source[5] = 0xb;
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	struct ipv6hdr *ip6 = data + ETH_HLEN;
	ip6->version = 6;
	ip6->nexthdr = IPPROTO_DSTOPTS;
	ip6->payload_len = bpf_htons(PACKET_SIZE - ETH_HLEN - sizeof(struct ipv6hdr));
	ip6->saddr.in6_u.u6_addr32[0] = bpf_htonl(saddr0);
	ip6->saddr.in6_u.u6_addr32[1] = bpf_htonl(saddr1);
	ip6->saddr.in6_u.u6_addr32[2] = bpf_htonl(saddr2);
	ip6->saddr.in6_u.u6_addr32[3] = bpf_htonl(saddr3);
	ip6->daddr.in6_u.u6_addr32[0] = bpf_htonl(daddr0);
	ip6->daddr.in6_u.u6_addr32[1] = bpf_htonl(daddr1);
	ip6->daddr.in6_u.u6_addr32[2] = bpf_htonl(daddr2);
	ip6->daddr.in6_u.u6_addr32[3] = bpf_htonl(daddr3);

	// Create a large extension header chain that approaches but doesn't exceed 512 bytes
	// This will exercise the fast path boundary checking
	__u32 offset = ETH_HLEN + sizeof(struct ipv6hdr);
	__u8 *ext_hdr;

	// First extension: Destination Options (200 bytes)
	ext_hdr = data + offset;
	ext_hdr[0] = IPPROTO_DSTOPTS;
	ext_hdr[1] = (200 / 8) - 1;  // 24 = 200 bytes
	offset += 200;

	// Second extension: Hop-by-Hop Options (200 bytes)
	ext_hdr = data + offset;
	ext_hdr[0] = IPPROTO_HOPOPTS;
	ext_hdr[1] = (200 / 8) - 1;
	offset += 200;

	// Third extension: Routing header (30 bytes)
	ext_hdr = data + offset;
	ext_hdr[0] = IPPROTO_ROUTING;
	ext_hdr[1] = (30 / 8) - 1;
	offset += 30;

	// Last extension points to L4
	ext_hdr = data + offset;
	ext_hdr[0] = l4proto;
	ext_hdr[1] = 0;  // 8 bytes
	offset += 8;

	// Add L4 header at the calculated position
	if (l4proto == IPPROTO_UDP) {
		struct udphdr *udp = data + offset;
		udp->source = bpf_htons(sport);
		udp->dest = bpf_htons(dport);
		udp->len = bpf_htons(8);
		udp->check = 0;
	} else {
		struct tcphdr *tcp = data + offset;
		tcp->source = bpf_htons(sport);
		tcp->dest = bpf_htons(dport);
		tcp->syn = 1;
		tcp->ack = 0;
		tcp->doff = 5;
	}

	return TC_ACT_OK;
}
