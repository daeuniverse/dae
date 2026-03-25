// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

//go:build exclude

// Keep BPF tests close to production code size by default.
// Enable verbose debug output only when explicitly requested via CFLAGS:
//   -D__BPF_TEST_ENABLE_DEBUG
#ifdef __BPF_TEST_ENABLE_DEBUG
#define __DEBUG
#define __DEBUG_ROUTING
#define __PRINT_ROUTING_RESULT
#endif
#define __BPF_TEST_DISABLE_LPM_CACHE  // Disable LPM cache in test mode

#include "../tproxy.c"
#include "./bpf_test.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map SEC(".maps") = {
	.values = {
		[0] = &tproxy_wan_egress_l2,
	},
};

struct test_routing_cache_ctx {
	struct tuples_key key;
	struct routing_result result;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct test_routing_cache_ctx);
	__uint(max_entries, 1);
} test_routing_cache_ctx_map SEC(".maps");

static __always_inline int
setup_cached_routing_result(__u32 saddr, __u32 daddr,
			    __u16 sport, __u16 dport,
			    __u8 outbound, __u32 mark)
{
	struct test_routing_cache_ctx *ctx =
		bpf_map_lookup_elem(&test_routing_cache_ctx_map, &zero_key);

	if (!ctx)
		return TC_ACT_SHOT;

	__builtin_memset(ctx, 0, sizeof(*ctx));
	ctx->key.sip.u6_addr32[2] = bpf_htonl(0xffff);
	ctx->key.sip.u6_addr32[3] = bpf_htonl(saddr);
	ctx->key.dip.u6_addr32[2] = bpf_htonl(0xffff);
	ctx->key.dip.u6_addr32[3] = bpf_htonl(daddr);
	ctx->key.sport = bpf_htons(sport);
	ctx->key.dport = bpf_htons(dport);
	ctx->key.l4proto = IPPROTO_TCP;
	ctx->result.outbound = outbound;
	ctx->result.mark = mark;

	// Scheme3: Store routing result in tcp_conn_state_map instead of routing_tuples_map
	struct tcp_conn_state conn_state = {};

	conn_state.is_wan_ingress_direction = false;
	conn_state.state = 0; // TCP_STATE_ACTIVE
	conn_state.last_seen_ns = bpf_ktime_get_ns();
	conn_state.has_routing = 1;
	conn_state.outbound = outbound;
	conn_state.mark = mark;
	conn_state.must = 0;

	return bpf_map_update_elem(&tcp_conn_state_map, &ctx->key, &conn_state, BPF_ANY);
}

SEC("tc/pktgen/dport_match")
int testpktgen_dport_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/dport_match")
int testsetup_dport_match(struct __sk_buff *skb)
{
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/dport_mismatch")
int testpktgen_dport_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/dport_mismatch")
int testsetup_dport_mismatch(struct __sk_buff *skb)
{
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/ipset_match")
int testpktgen_ipset_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(100,64,0,2), 19233, 80);
}

SEC("tc/setup/ipset_match")
int testsetup_ipset_match(struct __sk_buff *skb)
{
	/* dip(100.64.0.0/16) -> direct */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 112, // */16
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0x64400000); // 100.64.0.0
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      IPV4(192,168,0,1), IPV4(100,64,0,2),
				      19233, 80);
}

SEC("tc/pktgen/ipset_mismatch")
int testpktgen_ipset_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(100,65,0,2), 19233, 80);
}

SEC("tc/setup/ipset_mismatch")
int testsetup_ipset_mismatch(struct __sk_buff *skb)
{
	// dip(100.64.0.0/16) -> direct
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 112, // */16
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0x64400000); // 100.64.0.0
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(100,65,0,2),
				      19233, 80);
}

SEC("tc/pktgen/source_ipset_match")
int testpktgen_source_ipset_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,50,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/source_ipset_match")
int testsetup_source_ipset_match(struct __sk_buff *skb)
{
	/* sip(192.168.50.0/24) -> direct */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_SourceIpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 120,
	};
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      IPV4(192,168,50,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/source_ipset_mismatch")
int testpktgen_source_ipset_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,51,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/source_ipset_mismatch")
int testsetup_source_ipset_mismatch(struct __sk_buff *skb)
{
	/* sip(192.168.50.0/24) -> direct */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_SourceIpSet;
	ms.outbound = 0;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 120,
	};
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,51,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/sport_match")
int testpktgen_sport_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/sport_match")
int testsetup_sport_match(struct __sk_buff *skb)
{
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/sport_mismatch")
int testpktgen_sport_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/sport_mismatch")
int testsetup_sport_mismatch(struct __sk_buff *skb)
{
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/tcp_non_syn_mark_restore")
int testpktgen_tcp_non_syn_mark_restore(struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,0,1), IPV4(1,1,1,1),
				       19233, 80,
				       false, true, true);
}

SEC("tc/setup/tcp_non_syn_mark_restore")
int testsetup_tcp_non_syn_mark_restore(struct __sk_buff *skb)
{
	int ret = setup_cached_routing_result(IPV4(192,168,0,1), IPV4(1,1,1,1),
					      19233, 80, 0, TPROXY_MARK);

	if (ret)
		return TC_ACT_SHOT;

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/tcp_non_syn_mark_restore")
int testcheck_tcp_non_syn_mark_restore(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_OK, TPROXY_MARK);
}

SEC("tc/pktgen/tcp_non_syn_cached_proxy_redirect")
int testpktgen_tcp_non_syn_cached_proxy_redirect(struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,0,1), IPV4(8,8,8,8),
				       23456, 443,
				       false, true, false);
}

SEC("tc/setup/tcp_non_syn_cached_proxy_redirect")
int testsetup_tcp_non_syn_cached_proxy_redirect(struct __sk_buff *skb)
{
	int ret = setup_cached_routing_result(IPV4(192,168,0,1), IPV4(8,8,8,8),
					      23456, 443,
					      OUTBOUND_USER_DEFINED_MIN,
					      TPROXY_MARK);

	if (ret)
		return TC_ACT_SHOT;

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/tcp_non_syn_cached_proxy_redirect")
int testcheck_tcp_non_syn_cached_proxy_redirect(struct __sk_buff *skb)
{
	return check_redirect_non_syn_tcp(skb);
}

SEC("tc/pktgen/l4proto_match")
int testpktgen_l4proto_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/l4proto_match")
int testsetup_l4proto_match(struct __sk_buff *skb)
{
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/l4proto_mismatch")
int testpktgen_l4proto_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/l4proto_mismatch")
int testsetup_l4proto_mismatch(struct __sk_buff *skb)
{
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/ipversion_match")
int testpktgen_ipversion_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/ipversion_match")
int testsetup_ipversion_match(struct __sk_buff *skb)
{
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/ipversion_mismatch")
int testpktgen_ipversion_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/ipversion_mismatch")
int testsetup_ipversion_mismatch(struct __sk_buff *skb)
{
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/mac_match")
int testpktgen_mac_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/mac_match")
int testsetup_mac_match(struct __sk_buff *skb)
{
	/* mac('06:07:08:09:0a:0b') -> proxy */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_Mac;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 128,
	};
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
	struct lpm_key lpm_key = {
		.prefixlen = 128,
	};
	__u8 *data = (__u8 *)&lpm_key.data;

	data[10] = 0x6;
	data[11] = 0x7;
	data[12] = 0x8;
	data[13] = 0x9;
	data[14] = 0xa;
	data[15] = 0xb;
	bpf_map_delete_elem(&unused_lpm_type, &lpm_key);

	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/mac_mismatch")
int testpktgen_mac_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/mac_mismatch")
int testsetup_mac_mismatch(struct __sk_buff *skb)
{
	/* mac('00:01:02:03:04:05') -> proxy */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_Mac;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 128,
	};
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/dscp_match")
int testpktgen_dscp_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/dscp_match")
int testsetup_dscp_match(struct __sk_buff *skb)
{
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/dscp_mismatch")
int testpktgen_dscp_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/dscp_mismatch")
int testsetup_dscp_mismatch(struct __sk_buff *skb)
{
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/and_match_1")
int testpktgen_and_match_1(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/and_match_1")
int testsetup_and_match_1(struct __sk_buff *skb)
{
	/* dip(1.1.0.0/16) && l4proto(tcp) && dport(1-1023, 8443) -> proxy */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 112, // */16
	};
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/and_match_2")
int testpktgen_and_match_2(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 8443);
}

SEC("tc/setup/and_match_2")
int testsetup_and_match_2(struct __sk_buff *skb)
{
	/* dip(1.1.0.0/16) && l4proto(tcp) && dport(1-1023, 8443) -> proxy */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 112, // */16
	};
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 8443);
}

SEC("tc/pktgen/and_mismatch")
int testpktgen_and_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 2333);
}

SEC("tc/setup/and_mismatch")
int testsetup_and_mismatch(struct __sk_buff *skb)
{
	/* dip(1.1.0.0/16) && l4proto(tcp) && dport(1-1023, 8443) -> proxy */
	struct match_set ms = {};

	ms.not = false;
	ms.type = MatchType_IpSet;
	ms.outbound = OUTBOUND_LOGICAL_AND;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	struct lpm_key lpm_key = {
		.prefixlen = 112, // */16
	};
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
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 2333);
}

SEC("tc/pktgen/not_match")
int testpktgen_not_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/not_match")
int testsetup_not_match(struct __sk_buff *skb)
{
	/* !dport(80) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {80, 80};

	ms.port_range = pr;
	ms.not = true;
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

SEC("tc/check/not_match")
int testcheck_not_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_OK,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/not_mismtach")
int testpktgen_not_mismtach(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/not_mismtach")
int testsetup_not_mismtach(struct __sk_buff *skb)
{
	/* !dport(80) -> proxy */
	struct match_set ms = {};
	struct port_range pr = {80, 80};

	ms.port_range = pr;
	ms.not = true;
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

SEC("tc/check/not_mismtach")
int testcheck_not_mismtach(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}
