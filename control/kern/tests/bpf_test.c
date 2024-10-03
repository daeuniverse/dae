// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>

//go:build exclude

#define __DEBUG
#define __DEBUG_ROUTING
#define __PRINT_ROUTING_RESULT

#include "../tproxy.c"
#include "./bpf_test.h"

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

SEC("tc/pktgen/dport_match")
int testpktgen_dport_match(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 80);
}

SEC("tc/setup/dport_match")
int testsetup_dport_match(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* dport(80) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {80, 80};
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dport_match")
int testcheck_dport_match(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      0xc0a80001, 0x01010101,
				      19233, 80);
}

SEC("tc/pktgen/dport_mismatch")
int testpktgen_dport_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 79);
}

SEC("tc/setup/dport_mismatch")
int testsetup_dport_mismatch(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* dport(80) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {80, 80};
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dport_mismatch")
int testcheck_dport_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:79
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      0xc0a80001, 0x01010101,
				      19233, 79);
}

SEC("tc/pktgen/ipset_match")
int testpktgen_ipset_match(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 224.1.0.2:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0xe0010002, 19233, 80);
}

SEC("tc/setup/ipset_match")
int testsetup_ipset_match(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* dip(224.1.0.0/16) -> direct */
	struct match_set ms = {};
	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {};
	lpm_key.trie_key.prefixlen = 112; // */16
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0xe0010000); // 224.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipset_match")
int testcheck_ipset_match(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 224.1.0.2:80
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      0xc0a80001, 0xe0010002,
				      19233, 80);
}

SEC("tc/pktgen/ipset_mismatch")
int testpktgen_ipset_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 225.1.0.2:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0xe1010002, 19233, 80);
}

SEC("tc/setup/ipset_mismatch")
int testsetup_ipset_mismatch(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	// dip(224.1.0.0/16) -> direct
	struct match_set ms = {};
	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {};
	lpm_key.trie_key.prefixlen = 112; // */16
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0xe0010000); // 224.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipset_mismatch")
int testcheck_ipset_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 225.1.0.2:80
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      0xc0a80001, 0xe1010002,
				      19233, 80);
}

SEC("tc/pktgen/source_ipset_match")
int testpktgen_source_ipset_match(struct __sk_buff *skb)
{
	// 192.168.50.1:19233 -> 224.1.0.2:80
	return set_ipv4_tcp(skb, 0xc0a83201, 0xe0010002, 19233, 80);
}

SEC("tc/setup/source_ipset_match")
int testsetup_source_ipset_match(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* sip(192.168.50.0/24) -> direct */
	struct match_set ms = {};
	ms.not = false;
	ms.type = MatchType_SourceIpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {};
	lpm_key.trie_key.prefixlen = 120;
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0xc0a83200); // 192.168.50.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/source_ipset_match")
int testcheck_source_ipset_match(struct __sk_buff *skb)
{
	// 192.168.50.1:19233 -> 224.1.0.2:80
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      0xc0a83201, 0xe0010002,
				      19233, 80);
}

SEC("tc/pktgen/source_ipset_mismatch")
int testpktgen_source_ipset_mismatch(struct __sk_buff *skb)
{
	// 192.168.51.1:19233 -> 224.1.0.2:80
	return set_ipv4_tcp(skb, 0xc0a83301, 0xe0010002, 19233, 80);
}

SEC("tc/setup/source_ipset_mismatch")
int testsetup_source_ipset_mismatch(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* sip(192.168.50.0/24) -> direct */
	struct match_set ms = {};
	ms.not = false;
	ms.type = MatchType_SourceIpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {};
	lpm_key.trie_key.prefixlen = 120;
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0xc0a83200); // 192.168.50.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/source_ipset_mismatch")
int testcheck_source_ipset_mismatch(struct __sk_buff *skb)
{
	// 192.168.51.1:19233 -> 224.1.0.2:80
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      0xc0a83301, 0xe0010002,
				      19233, 80);
}

SEC("tc/pktgen/sport_match")
int testpktgen_sport_match(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 80);
}

SEC("tc/setup/sport_match")
int testsetup_sport_match(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* sport(19000-20000) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {19000, 20000};
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_SourcePort;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/sport_match")
int testcheck_sport_match(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      0xc0a80001, 0x01010101,
				      19233, 80);
}

SEC("tc/pktgen/sport_mismatch")
int testpktgen_sport_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 79);
}

SEC("tc/setup/sport_mismatch")
int testsetup_sport_mismatch(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* sport(19230-19232) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {19230, 19232};
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_SourcePort;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/sport_mismatch")
int testcheck_sport_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:79
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      0xc0a80001, 0x01010101,
				      19233, 79);
}

SEC("tc/pktgen/l4proto_match")
int testpktgen_l4proto_match(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 79);
}

SEC("tc/setup/l4proto_match")
int testsetup_l4proto_match(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* l4proto(tcp) -> proxy */
	struct match_set ms = {};
	ms.l4proto_type = L4ProtoType_TCP;
	ms.not = false;
	ms.type = MatchType_L4Proto;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/l4proto_match")
int testcheck_l4proto_match(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:79
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      0xc0a80001, 0x01010101,
				      19233, 79);
}

SEC("tc/pktgen/l4proto_mismatch")
int testpktgen_l4proto_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 79);
}

SEC("tc/setup/l4proto_mismatch")
int testsetup_l4proto_mismatch(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* l4proto(udp) -> proxy */
	struct match_set ms = {};
	ms.l4proto_type = L4ProtoType_UDP;
	ms.not = false;
	ms.type = MatchType_L4Proto;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/l4proto_mismatch")
int testcheck_l4proto_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:79
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      0xc0a80001, 0x01010101,
				      19233, 79);
}

SEC("tc/pktgen/ipversion_match")
int testpktgen_ipversion_match(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 79);
}

SEC("tc/setup/ipversion_match")
int testsetup_ipversion_match(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* ipversion(4) -> proxy */
	struct match_set ms = {};
	ms.ip_version = IpVersionType_4;
	ms.not = false;
	ms.type = MatchType_IpVersion;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipversion_match")
int testcheck_ipversion_match(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:79
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      0xc0a80001, 0x01010101,
				      19233, 79);
}

SEC("tc/pktgen/ipversion_mismatch")
int testpktgen_ipversion_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 79);
}

SEC("tc/setup/ipversion_mismatch")
int testsetup_ipversion_mismatch(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* ipversion(6) -> proxy */
	struct match_set ms = {};
	ms.ip_version = IpVersionType_6;
	ms.not = false;
	ms.type = MatchType_IpVersion;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipversion_mismatch")
int testcheck_ipversion_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:79
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      0xc0a80001, 0x01010101,
				      19233, 79);
}

SEC("tc/pktgen/mac_match")
int testpktgen_mac_match(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 79);
}

SEC("tc/setup/mac_match")
int testsetup_mac_match(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* mac('06:07:08:09:0a:0b') -> proxy */
	struct match_set ms = {};
	ms.not = false;
	ms.type = MatchType_Mac;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {};
	lpm_key.trie_key.prefixlen = 128;
	__u8 *data = (__u8 *)&lpm_key.data;
	data[10] = 0x6;
	data[11] = 0x7;
	data[12] = 0x8;
	data[13] = 0x9;
	data[14] = 0xa;
	data[15] = 0xb;
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/mac_match")
int testcheck_mac_match(struct __sk_buff *skb)
{
	struct lpm_key lpm_key = {};
	lpm_key.trie_key.prefixlen = 128;
	__u8 *data = (__u8 *)&lpm_key.data;
	data[10] = 0x6;
	data[11] = 0x7;
	data[12] = 0x8;
	data[13] = 0x9;
	data[14] = 0xa;
	data[15] = 0xb;
	bpf_map_delete_elem(&unused_lpm_type, &lpm_key);

	// 192.168.0.1:19233 -> 1.1.1.1:79
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      0xc0a80001, 0x01010101,
				      19233, 79);
}

SEC("tc/pktgen/mac_mismatch")
int testpktgen_mac_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 79);
}

SEC("tc/setup/mac_mismatch")
int testsetup_mac_mismatch(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* mac('00:01:02:03:04:05') -> proxy */
	struct match_set ms = {};
	ms.not = false;
	ms.type = MatchType_Mac;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {};
	lpm_key.trie_key.prefixlen = 128;
	__u8 *data = (__u8 *)&lpm_key.data;
	data[10] = 0x0;
	data[11] = 0x1;
	data[12] = 0x2;
	data[13] = 0x3;
	data[14] = 0x4;
	data[15] = 0x5;
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/mac_mismatch")
int testcheck_mac_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:79
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      0xc0a80001, 0x01010101,
				      19233, 79);
}

SEC("tc/pktgen/dscp_match")
int testpktgen_dscp_match(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 79);
}

SEC("tc/setup/dscp_match")
int testsetup_dscp_match(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* dscp(4) -> proxy */
	struct match_set ms = {};
	ms.dscp = 4;
	ms.not = false;
	ms.type = MatchType_Dscp;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dscp_match")
int testcheck_dscp_match(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:79
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      0xc0a80001, 0x01010101,
				      19233, 79);
}

SEC("tc/pktgen/dscp_mismatch")
int testpktgen_dscp_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 79);
}

SEC("tc/setup/dscp_mismatch")
int testsetup_dscp_mismatch(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* dscp(5) -> proxy */
	struct match_set ms = {};
	ms.dscp = 5;
	ms.not = false;
	ms.type = MatchType_Dscp;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dscp_mismatch")
int testcheck_dscp_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:79
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      0xc0a80001, 0x01010101,
				      19233, 79);
}

SEC("tc/pktgen/and_match_1")
int testpktgen_and_match_1(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:80
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 79);
}

SEC("tc/setup/and_match_1")
int testsetup_and_match_1(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* dip(1.1.0.0/16) && l4proto(tcp) && dport(1-1023, 8443) -> proxy */
	struct match_set ms = {};
	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {};
	lpm_key.trie_key.prefixlen = 112; // */16
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0x01010000); // 1.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	ms.l4proto_type = L4ProtoType_TCP;
	ms.not = false;
	ms.type = MatchType_L4Proto;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &one_key, &ms, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	struct port_range pr = {1, 1023};
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_LOGICAL_OR;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &two_key, &ms, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	pr.port_start = 8443;
	pr.port_end = 8443;
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &three_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	ms.not = false;
	ms.type = MatchType_Fallback;
	ms.outbound = OUTBOUND_DIRECT;
	ms.must = true;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &four_key, &ms, BPF_ANY);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/and_match_1")
int testcheck_and_match_1(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:79
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      0xc0a80001, 0x01010101,
				      19233, 79);
}

SEC("tc/pktgen/and_match_2")
int testpktgen_and_match_2(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:8443
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 8443);
}

SEC("tc/setup/and_match_2")
int testsetup_and_match_2(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* dip(1.1.0.0/16) && l4proto(tcp) && dport(1-1023, 8443) -> proxy */
	struct match_set ms = {};
	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {};
	lpm_key.trie_key.prefixlen = 112; // */16
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0x01010000); // 1.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	ms.l4proto_type = L4ProtoType_TCP;
	ms.not = false;
	ms.type = MatchType_L4Proto;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &one_key, &ms, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	struct port_range pr = {1, 1023};
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_LOGICAL_OR;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &two_key, &ms, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	pr.port_start = 8443;
	pr.port_end = 8443;
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &three_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	ms.not = false;
	ms.type = MatchType_Fallback;
	ms.outbound = OUTBOUND_DIRECT;
	ms.must = true;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &four_key, &ms, BPF_ANY);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/and_match_2")
int testcheck_and_match_2(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:8443
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      0xc0a80001, 0x01010101,
				      19233, 8443);
}

SEC("tc/pktgen/and_mismatch")
int testpktgen_and_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:2333
	return set_ipv4_tcp(skb, 0xc0a80001, 0x01010101, 19233, 2333);
}

SEC("tc/setup/and_mismatch")
int testsetup_and_mismatch(struct __sk_buff *skb)
{
	__u32 linklen = ETH_HLEN;
	bpf_map_update_elem(&linklen_map, &one_key, &linklen, BPF_ANY);

	/* dip(1.1.0.0/16) && l4proto(tcp) && dport(1-1023, 8443) -> proxy */
	struct match_set ms = {};
	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {};
	lpm_key.trie_key.prefixlen = 112; // */16
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0x01010000); // 1.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	ms.l4proto_type = L4ProtoType_TCP;
	ms.not = false;
	ms.type = MatchType_L4Proto;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &one_key, &ms, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	struct port_range pr = {1, 1023};
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_LOGICAL_OR;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &two_key, &ms, BPF_ANY);

	__builtin_memset(&ms, 0, sizeof(ms));
	pr.port_start = 8443;
	pr.port_end = 8443;
	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &three_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	ms.not = false;
	ms.type = MatchType_Fallback;
	ms.outbound = OUTBOUND_DIRECT;
	ms.must = true;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &four_key, &ms, BPF_ANY);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/and_mismatch")
int testcheck_and_mismatch(struct __sk_buff *skb)
{
	// 192.168.0.1:19233 -> 1.1.1.1:2333
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      0xc0a80001, 0x01010101,
				      19233, 2333);
}
