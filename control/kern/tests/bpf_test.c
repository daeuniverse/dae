// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>

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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct domain_routing);
	__uint(max_entries, 1);
} test_domain_routing_scratch_map SEC(".maps");

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

// Scratch storage for writing conn_state_map entries without placing a
// ~56-byte struct on the BPF stack, which would push multi-call setup
// programs such as testsetup_wan_tcp_cached_outbound_survives_connectivity_change
// past the 512-byte verifier limit on older (5.x) kernels.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct conn_state);
	__uint(max_entries, 1);
} test_conn_state_scratch_map SEC(".maps");

static __always_inline int
setup_cached_routing_result_for_proto(__u32 saddr, __u32 daddr,
				      __u16 sport, __u16 dport,
				      __u8 l4proto, __u8 outbound,
				      __u32 mark)
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
	ctx->key.l4proto = l4proto;
	ctx->result.outbound = outbound;
	ctx->result.mark = mark;

	// Scheme3: Store routing result in conn_state_map instead of routing_tuples_map.
	// Use a percpu scratch map value instead of a stack-local struct, otherwise
	// deep call chains (setup -> do_tproxy_wan_egress -> ...) blow past the
	// 512-byte stack limit on 5.x kernels.
	struct conn_state *conn_state =
		bpf_map_lookup_elem(&test_conn_state_scratch_map, &zero_key);

	if (!conn_state)
		return TC_ACT_SHOT;
	__builtin_memset(conn_state, 0, sizeof(*conn_state));

	conn_state->is_wan_ingress_direction = false;
	conn_state->state = TCP_STATE_ACTIVE;
	conn_state->last_seen_ns = bpf_ktime_get_ns();
	conn_state->meta.data.has_routing = 1;
	conn_state->meta.data.outbound = outbound;
	conn_state->meta.data.mark = mark;
	conn_state->meta.data.must = 0;

	return bpf_map_update_elem(&conn_state_map, &ctx->key, conn_state, BPF_ANY);
}

static __always_inline int
setup_cached_routing_result(__u32 saddr, __u32 daddr,
			    __u16 sport, __u16 dport,
			    __u8 outbound, __u32 mark)
{
	return setup_cached_routing_result_for_proto(saddr, daddr, sport, dport,
					     IPPROTO_TCP, outbound, mark);
}

static __always_inline int
set_test_outbound_connectivity(__u8 outbound, __u8 l4proto, __u32 alive)
{
	__u32 domain_idx = l4proto == IPPROTO_UDP ? 2 : 0;
	__u32 key = ((__u32)outbound * 6) + (domain_idx * 2);

	return bpf_map_update_elem(&outbound_connectivity_map, &key, &alive,
				   BPF_ANY);
}

static __always_inline int
set_routing_epoch_port_rule(__u32 slot, __u16 port, __u8 outbound)
{
	struct match_set match_set = {};
	struct port_range port_range = {port, port};
	__u32 routing_key = slot * MAX_MATCH_SET_LEN;
	__u32 rules_len = 1;

	if (slot >= ROUTING_EPOCH_SLOT_NUM)
		return TC_ACT_SHOT;

	match_set.port_range = port_range;
	match_set.type = MatchType_Port;
	match_set.outbound = outbound;

	if (bpf_map_update_elem(&routing_map, &routing_key, &match_set, BPF_ANY))
		return TC_ACT_SHOT;
	if (bpf_map_update_elem(&routing_meta_map, &slot, &rules_len, BPF_ANY))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
setup_routing_epoch_lan_ingress(struct __sk_buff *skb, __u32 active_slot)
{
	__u32 slot_zero = 0;
	int ret;

	if (set_routing_epoch_port_rule(0, 443, OUTBOUND_USER_DEFINED_MIN))
		return TC_ACT_SHOT;
	if (set_routing_epoch_port_rule(1, 443,
					OUTBOUND_USER_DEFINED_MIN + 1))
		return TC_ACT_SHOT;
	if (bpf_map_update_elem(&active_routing_epoch_map, &zero_key,
				&active_slot, BPF_ANY))
		return TC_ACT_SHOT;

	ret = do_tproxy_lan_ingress(skb, ETH_HLEN);
	if (bpf_map_update_elem(&active_routing_epoch_map, &zero_key,
				&slot_zero, BPF_ANY))
		return TC_ACT_SHOT;
	return ret;
}

static __always_inline int
set_routing_epoch_domain_rule(__u32 slot, __u8 outbound, __u32 bitmap)
{
	struct match_set domain_rule = {};
	struct match_set fallback_rule = {};
	struct routing_epoch_ip ip_key = {};
	struct domain_routing *projection;
	__u32 scratch_key = 0;
	__u32 domain_key = slot * MAX_MATCH_SET_LEN;
	__u32 fallback_key = domain_key + 1;
	__u32 rules_len = 2;

	if (slot >= ROUTING_EPOCH_SLOT_NUM)
		return TC_ACT_SHOT;

	domain_rule.type = MatchType_DomainSet;
	domain_rule.outbound = outbound;
	if (bpf_map_update_elem(&routing_map, &domain_key, &domain_rule,
				BPF_ANY))
		return TC_ACT_SHOT;

	fallback_rule.type = MatchType_Fallback;
	fallback_rule.outbound = OUTBOUND_USER_DEFINED_MIN + 2;
	if (bpf_map_update_elem(&routing_map, &fallback_key, &fallback_rule,
				BPF_ANY))
		return TC_ACT_SHOT;
	if (bpf_map_update_elem(&routing_meta_map, &slot, &rules_len,
				BPF_ANY))
		return TC_ACT_SHOT;

	// The packet generator below targets 198.51.100.20.
	ip_key.slot = slot;
	ip_key.addr[2] = bpf_htonl(0xffff);
	ip_key.addr[3] = bpf_htonl(0xc6336414);
	projection = bpf_map_lookup_elem(&test_domain_routing_scratch_map,
					 &scratch_key);
	if (!projection)
		return TC_ACT_SHOT;
	__builtin_memset(projection, 0, sizeof(*projection));
	projection->bitmap[0] = bitmap;
	return bpf_map_update_elem(&domain_routing_map, &ip_key, projection,
				   BPF_ANY);
}

static __always_inline int
setup_routing_epoch_domain_lan_ingress(struct __sk_buff *skb,
				       __u32 active_slot)
{
	__u32 zero_key = 0;
	int ret;

	// Only slot zero projects this destination into the domain rule.
	if (set_routing_epoch_domain_rule(0, OUTBOUND_USER_DEFINED_MIN, 1))
		return TC_ACT_SHOT;
	if (set_routing_epoch_domain_rule(1, OUTBOUND_USER_DEFINED_MIN + 1, 0))
		return TC_ACT_SHOT;
	if (bpf_map_update_elem(&active_routing_epoch_map, &zero_key,
				&active_slot, BPF_ANY))
		return TC_ACT_SHOT;

	ret = do_tproxy_lan_ingress(skb, ETH_HLEN);
	zero_key = 0;
	if (bpf_map_update_elem(&active_routing_epoch_map, &zero_key,
				&zero_key, BPF_ANY))
		return TC_ACT_SHOT;
	return ret;
}

static __always_inline int
check_routing_epoch_lan_ingress(struct __sk_buff *skb,
				__u32 expected_status_code,
				__u32 saddr, __u32 daddr,
				__u16 sport, __u16 dport,
				__u8 expected_outbound,
				__u8 expected_epoch_slot)
{
	struct tuples_key key = {};
	struct conn_state *conn_state;
	struct routing_handoff_entry *handoff;

	if (check_tcp_conn_state_ipv4_tcp(skb, expected_status_code,
					  saddr, daddr, sport, dport,
					  expected_outbound, 0, true))
		return TC_ACT_SHOT;

	key.sip.u6_addr32[2] = bpf_htonl(0xffff);
	key.sip.u6_addr32[3] = bpf_htonl(saddr);
	key.dip.u6_addr32[2] = bpf_htonl(0xffff);
	key.dip.u6_addr32[3] = bpf_htonl(daddr);
	key.sport = bpf_htons(sport);
	key.dport = bpf_htons(dport);
	key.l4proto = IPPROTO_TCP;

	conn_state = bpf_map_lookup_elem(&conn_state_map, &key);
	if (!conn_state || conn_state->routing_epoch_slot != expected_epoch_slot ||
	    conn_state->datapath_generation != PARAM.datapath_generation) {
		bpf_printk("conn_state routing epoch slot mismatch\n");
		return TC_ACT_SHOT;
	}

	handoff = bpf_map_lookup_elem(&routing_handoff_map, &key);
	if (!handoff || handoff->result.outbound != expected_outbound ||
	    handoff->result.routing_epoch_slot != expected_epoch_slot ||
	    handoff->result.datapath_generation != PARAM.datapath_generation) {
		bpf_printk("routing handoff epoch attribution mismatch\n");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
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
				      DAE_TC_CONTINUE,
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
				      DAE_TC_CONTINUE,
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
				      DAE_TC_CONTINUE,
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
				      DAE_TC_CONTINUE,
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

SEC("tc/pktgen/tcp_non_syn_stateless_passthrough")
int testpktgen_tcp_non_syn_stateless_passthrough(struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,0,1), IPV4(8,8,4,4),
				       23456, 443,
				       false, true, true);
}

SEC("tc/setup/tcp_non_syn_stateless_passthrough")
int testsetup_tcp_non_syn_stateless_passthrough(struct __sk_buff *skb)
{
	struct match_set ms = {};
	struct port_range pr = {443, 443};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/tcp_non_syn_stateless_passthrough")
int testcheck_tcp_non_syn_stateless_passthrough(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_OK, 0);
}

SEC("tc/pktgen/wan_egress_tcp_non_syn_cached_proxy_redirect")
int testpktgen_wan_egress_tcp_non_syn_cached_proxy_redirect(struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,10,1), IPV4(9,9,9,9),
				       34567, 443,
				       false, true, false);
}

SEC("tc/setup/wan_egress_tcp_non_syn_cached_proxy_redirect")
int testsetup_wan_egress_tcp_non_syn_cached_proxy_redirect(struct __sk_buff *skb)
{
	int ret = setup_cached_routing_result(IPV4(192,168,10,1), IPV4(9,9,9,9),
					      34567, 443,
					      OUTBOUND_USER_DEFINED_MIN,
					      TPROXY_MARK);

	if (ret)
		return TC_ACT_SHOT;

	return do_tproxy_wan_egress(skb, 14, NULL);
}

SEC("tc/check/wan_egress_tcp_non_syn_cached_proxy_redirect")
int testcheck_wan_egress_tcp_non_syn_cached_proxy_redirect(struct __sk_buff *skb)
{
	struct tuples_key key = {};

	if (check_redirect_non_syn_tcp(skb) != TC_ACT_OK)
		return TC_ACT_SHOT;
	key.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key.sip.u6_addr32[3] = bpf_htonl(IPV4(192,168,10,1));
	key.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key.dip.u6_addr32[3] = bpf_htonl(IPV4(9,9,9,9));
	key.sport = bpf_htons(34567);
	key.dport = bpf_htons(443);
	key.l4proto = IPPROTO_TCP;
	if (bpf_map_lookup_elem(&routing_handoff_map, &key)) {
		bpf_printk("steady TCP routing handoff was written\n");
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}

SEC("tc/pktgen/wan_egress_tcp_non_syn_stateless_passthrough")
int testpktgen_wan_egress_tcp_non_syn_stateless_passthrough(struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,10,2), IPV4(9,9,9,10),
				       34568, 443,
				       false, true, true);
}

SEC("tc/setup/wan_egress_tcp_non_syn_stateless_passthrough")
int testsetup_wan_egress_tcp_non_syn_stateless_passthrough(struct __sk_buff *skb)
{
	struct match_set ms = {};
	struct port_range pr = {443, 443};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	return do_tproxy_wan_egress(skb, 14, NULL);
}

SEC("tc/check/wan_egress_tcp_non_syn_stateless_passthrough")
int testcheck_wan_egress_tcp_non_syn_stateless_passthrough(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, DAE_TC_CONTINUE, 0);
}

SEC("tc/pktgen/wan_egress_tcp_syn_redirect_track")
int testpktgen_wan_egress_tcp_syn_redirect_track(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,10,3), IPV4(9,9,9,11),
			    34569, 443);
}

SEC("tc/setup/wan_egress_tcp_syn_redirect_track")
int testsetup_wan_egress_tcp_syn_redirect_track(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/wan_egress_tcp_syn_redirect_track")
int testcheck_wan_egress_tcp_syn_redirect_track(struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto_and_track_ipv4(skb,
								   IPPROTO_TCP,
								   1);
}

SEC("tc/pktgen/wan_egress_udp_redirect_track")
int testpktgen_wan_egress_udp_redirect_track(struct __sk_buff *skb)
{
	return set_ipv4_udp_fastpath_with_dscp(skb,
					   IPV4(192,168,10,3), IPV4(9,9,9,11),
					   34569, 443, 0);
}

SEC("tc/setup/wan_egress_udp_redirect_track")
int testsetup_wan_egress_udp_redirect_track(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/wan_egress_udp_redirect_track")
int testcheck_wan_egress_udp_redirect_track(struct __sk_buff *skb)
{
	struct tuples_key key = {};

	if (check_redirect_with_listener_l4proto_and_track_ipv4(
			skb, IPPROTO_UDP, 1) != TC_ACT_OK)
		return TC_ACT_SHOT;
	key.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key.sip.u6_addr32[3] = bpf_htonl(IPV4(192,168,10,3));
	key.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key.dip.u6_addr32[3] = bpf_htonl(IPV4(9,9,9,11));
	key.sport = bpf_htons(34569);
	key.dport = bpf_htons(443);
	key.l4proto = IPPROTO_UDP;
	if (!bpf_map_lookup_elem(&routing_handoff_map, &key)) {
		bpf_printk("new UDP routing handoff is missing\n");
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}

SEC("tc/pktgen/wan_egress_udp_expired_state_recreates_handoff")
int testpktgen_wan_egress_udp_expired_state_recreates_handoff(struct __sk_buff *skb)
{
	return set_ipv4_udp_fastpath_with_dscp(
		skb, IPV4(192,168,11,3), IPV4(9,9,9,12), 34570, 8443, 0);
}

SEC("tc/setup/wan_egress_udp_expired_state_recreates_handoff")
int testsetup_wan_egress_udp_expired_state_recreates_handoff(
	struct __sk_buff *skb)
{
	struct test_routing_cache_ctx *ctx;
	struct conn_state *state;

	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);
	if (setup_cached_routing_result_for_proto(
			IPV4(192,168,11,3), IPV4(9,9,9,12), 34570, 8443,
			IPPROTO_UDP, OUTBOUND_USER_DEFINED_MIN, TPROXY_MARK))
		return TC_ACT_SHOT;
	ctx = bpf_map_lookup_elem(&test_routing_cache_ctx_map, &zero_key);
	if (!ctx)
		return TC_ACT_SHOT;
	state = bpf_map_lookup_elem(&conn_state_map, &ctx->key);
	if (!state)
		return TC_ACT_SHOT;
	/* Seed a state that is expired by exactly one nanosecond. Test builds
	 * shorten UDP_CONN_STATE_TIMEOUT_NS (see the Makefile) so this stays a
	 * real past timestamp on a freshly booted host: with the production
	 * 300-second backstop the subtraction wraps, and the future-timestamp
	 * guard in udp_conn_state_expired() then keeps the entry alive, which
	 * would silently exercise the existing-state path instead.
	 */
	state->last_seen_ns =
		bpf_ktime_get_ns() - UDP_CONN_STATE_TIMEOUT_NS - 1;
	return do_tproxy_wan_egress(skb, ETH_HLEN, NULL);
}

SEC("tc/check/wan_egress_udp_expired_state_recreates_handoff")
int testcheck_wan_egress_udp_expired_state_recreates_handoff(
	struct __sk_buff *skb)
{
	struct tuples_key key = {};

	if (check_redirect_with_listener_l4proto(skb, IPPROTO_UDP) != TC_ACT_OK)
		return TC_ACT_SHOT;
	key.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key.sip.u6_addr32[3] = bpf_htonl(IPV4(192,168,11,3));
	key.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key.dip.u6_addr32[3] = bpf_htonl(IPV4(9,9,9,12));
	key.sport = bpf_htons(34570);
	key.dport = bpf_htons(8443);
	key.l4proto = IPPROTO_UDP;
	if (!bpf_map_lookup_elem(&conn_state_map, &key) ||
	    !bpf_map_lookup_elem(&routing_handoff_map, &key))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

SEC("tc/pktgen/lan_wan_egress_combined_udp_redirect")
int testpktgen_lan_wan_egress_combined_udp_redirect(struct __sk_buff *skb)
{
	return set_ipv4_udp_fastpath_with_dscp(
		skb, IPV4(192,168,30,1), IPV4(10,30,0,1), 43001, 8443, 0);
}

SEC("tc/setup/lan_wan_egress_combined_udp_redirect")
int testsetup_lan_wan_egress_combined_udp_redirect(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);
	return do_tproxy_lan_wan_egress(skb, ETH_HLEN);
}

SEC("tc/check/lan_wan_egress_combined_udp_redirect")
int testcheck_lan_wan_egress_combined_udp_redirect(struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto(skb, IPPROTO_UDP);
}

SEC("tc/pktgen/lan_wan_egress_combined_tcp_redirect")
int testpktgen_lan_wan_egress_combined_tcp_redirect(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,31,1), IPV4(10,31,0,1), 43101,
			    8443);
}

SEC("tc/setup/lan_wan_egress_combined_tcp_redirect")
int testsetup_lan_wan_egress_combined_tcp_redirect(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);
	return do_tproxy_lan_wan_egress(skb, ETH_HLEN);
}

SEC("tc/check/lan_wan_egress_combined_tcp_redirect")
int testcheck_lan_wan_egress_combined_tcp_redirect(struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto(skb, IPPROTO_TCP);
}

SEC("tc/pktgen/tcp_active_idle_state_retained")
int testpktgen_tcp_active_idle_state_retained(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,20,1), IPV4(10,20,0,1),
			    41000, 443);
}

SEC("tc/setup/tcp_active_idle_state_retained")
int testsetup_tcp_active_idle_state_retained(struct __sk_buff *skb)
{
	struct conn_state state = {};
	(void)skb;

	state.state = TCP_STATE_ACTIVE;
	state.last_seen_ns = 1;
	if (tcp_conn_state_expired(&state, 120000000002ULL))
		return TC_ACT_SHOT;

	state.state = TCP_STATE_CLOSING;
	if (tcp_conn_state_expired(
		    &state, state.last_seen_ns + TCP_CONN_STATE_CLOSING_TIMEOUT_NS))
		return TC_ACT_SHOT;
	if (!tcp_conn_state_expired(
		    &state,
		    state.last_seen_ns + TCP_CONN_STATE_CLOSING_TIMEOUT_NS + 1))
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

SEC("tc/check/tcp_active_idle_state_retained")
int testcheck_tcp_active_idle_state_retained(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_OK, 0);
}

SEC("tc/pktgen/tcp_pure_syn_preserves_live_state")
int testpktgen_tcp_pure_syn_preserves_live_state(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,20,2), IPV4(10,20,0,2),
			    41001, 443);
}

/*
  *: a pure SYN that reuses the tuple of a live ACTIVE flow (an illegal
 * mid-stream SYN the kernel answers with a challenge ACK) must not delete or
 * rewrite that flow's routing decision while the flow still belongs to the
 * current generation. Its liveness is still refreshed, a routingless entry
 * stays replaceable so the historical behavior for genuinely stale state is
 * preserved, and a SYN that cannot name the generation it was routed under
 * re-routes the flow instead of inheriting the cached routing.
 */
SEC("tc/setup/tcp_pure_syn_preserves_live_state")
int testsetup_tcp_pure_syn_preserves_live_state(struct __sk_buff *skb)
{
	struct tuples_key key = {};
	struct conn_state live_state = {};
	struct conn_state *cur_state;
	struct tcphdr tcph = {};
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	__u32 mark = 0;
	__u8 must = 0;
	__u64 now, before, rerouted_before;

	(void)skb;
	key.sip.u6_addr32[2] = bpf_htonl(0xffff);
	key.sip.u6_addr32[3] = bpf_htonl(IPV4(192,168,20,2));
	key.dip.u6_addr32[2] = bpf_htonl(0xffff);
	key.dip.u6_addr32[3] = bpf_htonl(IPV4(10,20,0,2));
	key.sport = bpf_htons(41001);
	key.dport = bpf_htons(443);
	key.l4proto = IPPROTO_TCP;
	now = bpf_ktime_get_ns();
	live_state.state = TCP_STATE_ACTIVE;
	live_state.last_seen_ns = now - 10000000000ULL;
	live_state.meta.data.has_routing = 1;
	live_state.meta.data.outbound = OUTBOUND_USER_DEFINED_MIN;
	live_state.routing_epoch_slot = routing_epoch_slot_encode(0);
	live_state.datapath_generation = PARAM.datapath_generation;
	if (bpf_map_update_elem(&conn_state_map, &key, &live_state, BPF_ANY))
		return TC_ACT_SHOT;

	before = ab_read_stat(BPF_STATS_SYN_REBIND_REJECTED);
	rerouted_before =
		ab_read_stat(BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE);
	tcph.syn = 1;
	/* Same epoch: a competing SYN must not rewrite the live flow, and its
	 * liveness must still be refreshed. */
	cur_state = mark_tcp_seen(&key, &tcph, false, &outbound, &mark, &must,
				  NULL, 0, NULL, 0,
				  routing_epoch_slot_encode(0));
	if (!cur_state || !cur_state->meta.data.has_routing ||
	    cur_state->state != TCP_STATE_ACTIVE)
		return TC_ACT_SHOT;
	if (cur_state->meta.data.outbound != OUTBOUND_USER_DEFINED_MIN)
		return TC_ACT_SHOT;
	if (cur_state->last_seen_ns <= bpf_ktime_get_ns() - 10000000000ULL)
		return TC_ACT_SHOT;
	if (ab_read_stat(BPF_STATS_SYN_REBIND_REJECTED) != before + 1)
		return TC_ACT_SHOT;
	if (ab_read_stat(BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE) !=
	    rerouted_before)
		return TC_ACT_SHOT;

	/* A routingless entry is still replaceable, and replacing it is not a
	 * generation change: there is no cached decision to replace. */
	if (bpf_map_delete_elem(&conn_state_map, &key))
		return TC_ACT_SHOT;
	__builtin_memset(&live_state, 0, sizeof(live_state));
	live_state.state = TCP_STATE_ACTIVE;
	live_state.last_seen_ns = now - 10000000000ULL;
	if (bpf_map_update_elem(&conn_state_map, &key, &live_state, BPF_ANY))
		return TC_ACT_SHOT;
	cur_state = mark_tcp_seen(&key, &tcph, false,
				  NULL, NULL, NULL, NULL,
				  0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN);
	if (!cur_state)
		return TC_ACT_SHOT;
	if (ab_read_stat(BPF_STATS_SYN_REBIND_REJECTED) != before + 1)
		return TC_ACT_SHOT;
	if (ab_read_stat(BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE) !=
	    rerouted_before)
		return TC_ACT_SHOT;

	/* A SYN that cannot name the generation it was routed under is not
	 * evidence of equality: the live flow's routing is not inherited by
	 * default, and the replacement is counted. This is the same-tuple SYN of
	 * a flow that outlived a rules change, with the packet's generation
	 * unreadable instead of merely different. */
	if (bpf_map_delete_elem(&conn_state_map, &key))
		return TC_ACT_SHOT;
	__builtin_memset(&live_state, 0, sizeof(live_state));
	live_state.state = TCP_STATE_ACTIVE;
	live_state.last_seen_ns = now - 10000000000ULL;
	live_state.meta.data.has_routing = 1;
	live_state.meta.data.outbound = OUTBOUND_USER_DEFINED_MIN;
	live_state.routing_epoch_slot = routing_epoch_slot_encode(0);
	live_state.datapath_generation = PARAM.datapath_generation;
	if (bpf_map_update_elem(&conn_state_map, &key, &live_state, BPF_ANY))
		return TC_ACT_SHOT;
	cur_state = mark_tcp_seen(&key, &tcph, false,
				  NULL, NULL, NULL, NULL,
				  0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN);
	if (cur_state && cur_state->meta.data.has_routing)
		return TC_ACT_SHOT;
	if (ab_read_stat(BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE) !=
	    rerouted_before + 1)
		return TC_ACT_SHOT;
	if (ab_read_stat(BPF_STATS_SYN_REBIND_REJECTED) != before + 1)
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

SEC("tc/check/tcp_pure_syn_preserves_live_state")
int testcheck_tcp_pure_syn_preserves_live_state(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_OK, 0);
}

SEC("tc/pktgen/lan_tcp_cached_outbound_survives_connectivity_change")
int testpktgen_lan_tcp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,20,3), IPV4(10,20,0,3),
				       41002, 443,
				       false, true, false);
}

SEC("tc/setup/lan_tcp_cached_outbound_survives_connectivity_change")
int testsetup_lan_tcp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	int ret;

	ret = setup_cached_routing_result(IPV4(192,168,20,3),
					  IPV4(10,20,0,3), 41002, 443,
					  outbound, TPROXY_MARK);
	if (ret || set_test_outbound_connectivity(outbound, IPPROTO_TCP, 0))
		return TC_ACT_SHOT;

	ret = do_tproxy_lan_ingress(skb, ETH_HLEN);
	if (set_test_outbound_connectivity(outbound, IPPROTO_TCP, 1))
		return TC_ACT_SHOT;
	return ret;
}

SEC("tc/check/lan_tcp_cached_outbound_survives_connectivity_change")
int testcheck_lan_tcp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return check_redirect_non_syn_tcp(skb);
}

SEC("tc/pktgen/wan_tcp_cached_outbound_survives_connectivity_change")
int testpktgen_wan_tcp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return set_ipv4_tcp_with_flags(skb,
				       IPV4(192,168,20,4), IPV4(10,20,0,4),
				       41003, 443,
				       false, true, false);
}

SEC("tc/setup/wan_tcp_cached_outbound_survives_connectivity_change")
int testsetup_wan_tcp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	int ret;

	ret = setup_cached_routing_result(IPV4(192,168,20,4),
					  IPV4(10,20,0,4), 41003, 443,
					  outbound, TPROXY_MARK);
	if (ret || set_test_outbound_connectivity(outbound, IPPROTO_TCP, 0))
		return TC_ACT_SHOT;

	ret = do_tproxy_wan_egress(skb, ETH_HLEN, NULL);
	if (set_test_outbound_connectivity(outbound, IPPROTO_TCP, 1))
		return TC_ACT_SHOT;
	return ret;
}

SEC("tc/check/wan_tcp_cached_outbound_survives_connectivity_change")
int testcheck_wan_tcp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return check_redirect_non_syn_tcp(skb);
}

SEC("tc/pktgen/lan_udp_cached_outbound_survives_connectivity_change")
int testpktgen_lan_udp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return set_ipv4_udp_fastpath_with_dscp(
		skb, IPV4(192,168,20,5), IPV4(10,20,0,5), 41004, 8443, 0);
}

SEC("tc/setup/lan_udp_cached_outbound_survives_connectivity_change")
int testsetup_lan_udp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	int ret;

	ret = setup_cached_routing_result_for_proto(
		IPV4(192,168,20,5), IPV4(10,20,0,5), 41004, 8443,
		IPPROTO_UDP, outbound, TPROXY_MARK);
	if (ret || set_test_outbound_connectivity(outbound, IPPROTO_UDP, 0))
		return TC_ACT_SHOT;

	ret = do_tproxy_lan_ingress(skb, ETH_HLEN);
	if (set_test_outbound_connectivity(outbound, IPPROTO_UDP, 1))
		return TC_ACT_SHOT;
	return ret;
}

SEC("tc/check/lan_udp_cached_outbound_survives_connectivity_change")
int testcheck_lan_udp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto(skb, IPPROTO_UDP);
}

SEC("tc/pktgen/wan_udp_cached_outbound_survives_connectivity_change")
int testpktgen_wan_udp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	return set_ipv4_udp_fastpath_with_dscp(
		skb, IPV4(192,168,20,6), IPV4(10,20,0,6), 41005, 8443, 0);
}

SEC("tc/setup/wan_udp_cached_outbound_survives_connectivity_change")
int testsetup_wan_udp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	int ret;

	ret = setup_cached_routing_result_for_proto(
		IPV4(192,168,20,6), IPV4(10,20,0,6), 41005, 8443,
		IPPROTO_UDP, outbound, TPROXY_MARK);
	if (ret || set_test_outbound_connectivity(outbound, IPPROTO_UDP, 0))
		return TC_ACT_SHOT;

	ret = do_tproxy_wan_egress(skb, ETH_HLEN, NULL);
	if (set_test_outbound_connectivity(outbound, IPPROTO_UDP, 1))
		return TC_ACT_SHOT;
	return ret;
}

SEC("tc/check/wan_udp_cached_outbound_survives_connectivity_change")
int testcheck_wan_udp_cached_outbound_survives_connectivity_change(
	struct __sk_buff *skb)
{
	struct tuples_key key = {};

	if (check_redirect_with_listener_l4proto_and_track_ipv4(
			skb, IPPROTO_UDP, 1) != TC_ACT_OK)
		return TC_ACT_SHOT;
	key.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key.sip.u6_addr32[3] = bpf_htonl(IPV4(192,168,20,6));
	key.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key.dip.u6_addr32[3] = bpf_htonl(IPV4(10,20,0,6));
	key.sport = bpf_htons(41005);
	key.dport = bpf_htons(8443);
	key.l4proto = IPPROTO_UDP;
	if (bpf_map_lookup_elem(&routing_handoff_map, &key)) {
		bpf_printk("steady UDP routing handoff was written\n");
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}

SEC("tc/pktgen/wan_tcp_new_outbound_obeys_connectivity_change")
int testpktgen_wan_tcp_new_outbound_obeys_connectivity_change(
	struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,20,7), IPV4(10,20,0,7),
			    41006, 443);
}

SEC("tc/setup/wan_tcp_new_outbound_obeys_connectivity_change")
int testsetup_wan_tcp_new_outbound_obeys_connectivity_change(
	struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	int ret;

	set_routing_fallback(outbound, false);
	if (set_test_outbound_connectivity(outbound, IPPROTO_TCP, 0))
		return TC_ACT_SHOT;

	ret = do_tproxy_wan_egress(skb, ETH_HLEN, NULL);
	if (set_test_outbound_connectivity(outbound, IPPROTO_TCP, 1))
		return TC_ACT_SHOT;
	return ret;
}

SEC("tc/check/wan_tcp_new_outbound_obeys_connectivity_change")
int testcheck_wan_tcp_new_outbound_obeys_connectivity_change(
	struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_SHOT, 0);
}

SEC("tc/pktgen/wan_udp_new_outbound_obeys_connectivity_change")
int testpktgen_wan_udp_new_outbound_obeys_connectivity_change(
	struct __sk_buff *skb)
{
	return set_ipv4_udp_fastpath_with_dscp(
		skb, IPV4(192,168,20,8), IPV4(10,20,0,8), 41007, 8443, 0);
}

SEC("tc/setup/wan_udp_new_outbound_obeys_connectivity_change")
int testsetup_wan_udp_new_outbound_obeys_connectivity_change(
	struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	int ret;

	set_routing_fallback(outbound, false);
	if (set_test_outbound_connectivity(outbound, IPPROTO_UDP, 0))
		return TC_ACT_SHOT;

	ret = do_tproxy_wan_egress(skb, ETH_HLEN, NULL);
	if (set_test_outbound_connectivity(outbound, IPPROTO_UDP, 1))
		return TC_ACT_SHOT;
	return ret;
}

SEC("tc/check/wan_udp_new_outbound_obeys_connectivity_change")
int testcheck_wan_udp_new_outbound_obeys_connectivity_change(
	struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_SHOT, 0);
}

// Blocked-event rate-limit regression. DAE_EVENT_BLOCKED (type 0) shares
// alive_block_rate_map with the per-outbound DAE_EVENT_BLOCKED_ALIVE
// domains. The reserved EVENT_RATE.blocked_key slot must resolve inside the
// ARRAY (previously 0xFFFFFFFF exceeded max_entries, so every lookup
// failed and type-0 emissions were suppressed forever) and each key must
// keep an independent 1s budget.
SEC("tc/pktgen/blocked_event_rate_limit")
int testpktgen_blocked_event_rate_limit(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 443);
}

SEC("tc/setup/blocked_event_rate_limit")
int testsetup_blocked_event_rate_limit(struct __sk_buff *skb)
{
	return TC_ACT_OK;
}

SEC("tc/check/blocked_event_rate_limit")
int testcheck_blocked_event_rate_limit(struct __sk_buff *skb)
{
	__u32 alive_key = OUTBOUND_USER_DEFINED_MIN;
	__u32 blocked_key = EVENT_RATE.blocked_key;
	__u64 now = bpf_ktime_get_ns();
	__u64 zero = 0;
	__u64 *last;

	// The type-0 slot must be resolvable; without it the limiter reports
	// "rate-limited" unconditionally and blocked events never emit.
	last = bpf_map_lookup_elem(&alive_block_rate_map, &blocked_key);
	if (!last) {
		bpf_printk("no alive_block_rate_map slot for blocked events\n");
		return TC_ACT_SHOT;
	}

	// Start from a known state: put the alive key inside its 1s window
	// (fresh timestamp) and the type-0 key outside it (timestamp 0, the
	// preallocated ARRAY default; the write also fails when the slot is
	// out of bounds).
	if (bpf_map_update_elem(&alive_block_rate_map, &alive_key, &now,
				BPF_ANY)) {
		bpf_printk("cannot arm alive rate-limit slot\n");
		return TC_ACT_SHOT;
	}
	if (bpf_map_update_elem(&alive_block_rate_map, &blocked_key, &zero,
				BPF_ANY)) {
		bpf_printk("cannot clear blocked rate-limit slot\n");
		return TC_ACT_SHOT;
	}

	// Per-outbound budget: a second blocked-alive emission for the same
	// outbound within 1s must be suppressed.
	if (!blocked_event_rate_limited(alive_key)) {
		bpf_printk("alive rate-limit slot ignored its 1s window\n");
		return TC_ACT_SHOT;
	}

	// Budget independence (alive -> blocked): the fresh alive timestamp
	// above must not throttle the type-0 key, so its first emission after
	// the 1s window is allowed. The test host has been up for at least 1s,
	// so the zeroed timestamp is always outside the window.
	if (blocked_event_rate_limited(blocked_key)) {
		bpf_printk("blocked rate-limit slot suppressed a clean emission\n");
		return TC_ACT_SHOT;
	}

	// The type-0 key now honours its own 1s budget.
	if (!blocked_event_rate_limited(blocked_key)) {
		bpf_printk("blocked rate-limit slot ignored its 1s window\n");
		return TC_ACT_SHOT;
	}

	// Budget independence (blocked -> alive), value-level: the type-0
	// emission above must not have refreshed the alive slot. The behaviour
	// check below cannot see a refresh - the fresh armed timestamp and a
	// rewritten one both throttle - so compare the stored value directly
	// with the armed timestamp: any write to the alive slot shows up here.
	last = bpf_map_lookup_elem(&alive_block_rate_map, &alive_key);
	if (!last) {
		bpf_printk("alive rate-limit slot vanished\n");
		return TC_ACT_SHOT;
	}
	if (*last != now) {
		bpf_printk("blocked emission refreshed the alive rate-limit slot\n");
		return TC_ACT_SHOT;
	}

	// Budget independence (blocked -> alive), behaviour-level: the type-0
	// emission above must not have reset the alive key's window.
	if (!blocked_event_rate_limited(alive_key)) {
		bpf_printk("blocked emission reset the alive rate-limit slot\n");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

SEC("tc/pktgen/lan_ingress_udp_first_fragment_listener")
int testpktgen_lan_ingress_udp_first_fragment_listener(struct __sk_buff *skb)
{
	return set_ipv4_udp_first_fragment(skb,
					   IPV4(192,168,0,1), IPV4(8,8,8,8),
					   5353, 1053);
}

SEC("tc/setup/lan_ingress_udp_first_fragment_listener")
int testsetup_lan_ingress_udp_first_fragment_listener(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);
	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_udp_first_fragment_listener")
int testcheck_lan_ingress_udp_first_fragment_listener(struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto(skb, IPPROTO_UDP);
}

SEC("tc/pktgen/lan_ingress_tcp_syn_first_fragment_listener")
int testpktgen_lan_ingress_tcp_syn_first_fragment_listener(struct __sk_buff *skb)
{
	return set_ipv4_tcp_first_fragment_with_flags(skb,
						      IPV4(192,168,0,1), IPV4(1,1,1,1),
						      19233, 443,
						      true, false, false);
}

SEC("tc/setup/lan_ingress_tcp_syn_first_fragment_listener")
int testsetup_lan_ingress_tcp_syn_first_fragment_listener(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);
	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_tcp_syn_first_fragment_listener")
int testcheck_lan_ingress_tcp_syn_first_fragment_listener(struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto(skb, IPPROTO_TCP);
}

SEC("tc/pktgen/lan_ingress_tcp_dscp_conn_state")
int testpktgen_lan_ingress_tcp_dscp_conn_state(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fastpath_with_dscp(skb,
					   IPV4(192,168,0,1), IPV4(1,1,1,1),
					   19233, 443, 10);
}

SEC("tc/setup/lan_ingress_tcp_dscp_conn_state")
int testsetup_lan_ingress_tcp_dscp_conn_state(struct __sk_buff *skb)
{
	struct match_set ms = {};
	struct port_range pr = {443, 443};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_tcp_dscp_conn_state")
int testcheck_lan_ingress_tcp_dscp_conn_state(struct __sk_buff *skb)
{
	return check_tcp_conn_state_ipv4_tcp_dscp(skb,
						  TC_ACT_REDIRECT,
						  IPV4(192,168,0,1), IPV4(1,1,1,1),
						  19233, 443,
						  OUTBOUND_USER_DEFINED_MIN,
						  0, 10, true);
}

SEC("tc/pktgen/routing_epoch_slot_zero_handoff")
int testpktgen_routing_epoch_slot_zero_handoff(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,0,10), IPV4(1,1,1,1),
			    24560, 443);
}

SEC("tc/setup/routing_epoch_slot_zero_handoff")
int testsetup_routing_epoch_slot_zero_handoff(struct __sk_buff *skb)
{
	return setup_routing_epoch_lan_ingress(skb, 0);
}

SEC("tc/check/routing_epoch_slot_zero_handoff")
int testcheck_routing_epoch_slot_zero_handoff(struct __sk_buff *skb)
{
	return check_routing_epoch_lan_ingress(skb, TC_ACT_REDIRECT,
						   IPV4(192,168,0,10), IPV4(1,1,1,1),
						   24560, 443,
						   OUTBOUND_USER_DEFINED_MIN,
						   routing_epoch_slot_encode(0));
}

SEC("tc/pktgen/routing_epoch_slot_one_handoff")
int testpktgen_routing_epoch_slot_one_handoff(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,0,11), IPV4(1,1,1,1),
			    24561, 443);
}

SEC("tc/setup/routing_epoch_slot_one_handoff")
int testsetup_routing_epoch_slot_one_handoff(struct __sk_buff *skb)
{
	return setup_routing_epoch_lan_ingress(skb, 1);
}

SEC("tc/check/routing_epoch_slot_one_handoff")
int testcheck_routing_epoch_slot_one_handoff(struct __sk_buff *skb)
{
	return check_routing_epoch_lan_ingress(skb, TC_ACT_REDIRECT,
						   IPV4(192,168,0,11), IPV4(1,1,1,1),
						   24561, 443,
						   OUTBOUND_USER_DEFINED_MIN + 1,
						   routing_epoch_slot_encode(1));
}

SEC("tc/pktgen/routing_epoch_domain_projection_slot_zero")
int testpktgen_routing_epoch_domain_projection_slot_zero(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(198,51,100,20),
			    19233, 443);
}

SEC("tc/setup/routing_epoch_domain_projection_slot_zero")
int testsetup_routing_epoch_domain_projection_slot_zero(struct __sk_buff *skb)
{
	return setup_routing_epoch_domain_lan_ingress(skb, 0);
}

SEC("tc/check/routing_epoch_domain_projection_slot_zero")
int testcheck_routing_epoch_domain_projection_slot_zero(struct __sk_buff *skb)
{
	return check_routing_epoch_lan_ingress(
		skb, TC_ACT_REDIRECT, IPV4(192,168,0,1),
		IPV4(198,51,100,20), 19233, 443, OUTBOUND_USER_DEFINED_MIN,
		routing_epoch_slot_encode(0));
}

SEC("tc/pktgen/routing_epoch_domain_projection_slot_one")
int testpktgen_routing_epoch_domain_projection_slot_one(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(198,51,100,20),
			    19233, 443);
}

SEC("tc/setup/routing_epoch_domain_projection_slot_one")
int testsetup_routing_epoch_domain_projection_slot_one(struct __sk_buff *skb)
{
	return setup_routing_epoch_domain_lan_ingress(skb, 1);
}

SEC("tc/check/routing_epoch_domain_projection_slot_one")
int testcheck_routing_epoch_domain_projection_slot_one(struct __sk_buff *skb)
{
	return check_routing_epoch_lan_ingress(
		skb, TC_ACT_REDIRECT, IPV4(192,168,0,1),
		IPV4(198,51,100,20), 19233, 443, OUTBOUND_USER_DEFINED_MIN + 2,
		routing_epoch_slot_encode(1));
}

SEC("tc/pktgen/lan_ingress_tcp_ipv6_dscp_conn_state")
int testpktgen_lan_ingress_tcp_ipv6_dscp_conn_state(struct __sk_buff *skb)
{
	return set_ipv6_tcp_fastpath_with_dscp(skb,
					   0x20010db8, 0, 0, 0x10,
					   0x26064700, 0, 0, 0x1111,
					   19233, 443, 10);
}

SEC("tc/setup/lan_ingress_tcp_ipv6_dscp_conn_state")
int testsetup_lan_ingress_tcp_ipv6_dscp_conn_state(struct __sk_buff *skb)
{
	struct match_set ms = {};
	struct port_range pr = {443, 443};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_tcp_ipv6_dscp_conn_state")
int testcheck_lan_ingress_tcp_ipv6_dscp_conn_state(struct __sk_buff *skb)
{
	return check_tcp_conn_state_ipv6_tcp_dscp(skb,
						  TC_ACT_REDIRECT,
						  0x20010db8, 0, 0, 0x10,
						  0x26064700, 0, 0, 0x1111,
						  19233, 443,
						  OUTBOUND_USER_DEFINED_MIN,
						  0, 10, true);
}

SEC("tc/pktgen/lan_ingress_udp_dscp_conn_state")
int testpktgen_lan_ingress_udp_dscp_conn_state(struct __sk_buff *skb)
{
	return set_ipv4_udp_fastpath_with_dscp(skb,
					   IPV4(192,168,0,1), IPV4(1,1,1,1),
					   24567, 443, 10);
}

SEC("tc/setup/lan_ingress_udp_dscp_conn_state")
int testsetup_lan_ingress_udp_dscp_conn_state(struct __sk_buff *skb)
{
	struct match_set ms = {};
	struct port_range pr = {443, 443};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_udp_dscp_conn_state")
int testcheck_lan_ingress_udp_dscp_conn_state(struct __sk_buff *skb)
{
	return check_udp_conn_state_ipv4_udp_dscp(skb,
						  TC_ACT_REDIRECT,
						  IPV4(192,168,0,1), IPV4(1,1,1,1),
						  24567, 443,
						  OUTBOUND_USER_DEFINED_MIN,
						  0, 10, true);
}

SEC("tc/pktgen/lan_ingress_udp_ipv6_dscp_conn_state")
int testpktgen_lan_ingress_udp_ipv6_dscp_conn_state(struct __sk_buff *skb)
{
	return set_ipv6_udp_fastpath_with_dscp(skb,
					   0x20010db8, 0, 0, 0x10,
					   0x26064700, 0, 0, 0x1111,
					   24567, 443, 10);
}

SEC("tc/setup/lan_ingress_udp_ipv6_dscp_conn_state")
int testsetup_lan_ingress_udp_ipv6_dscp_conn_state(struct __sk_buff *skb)
{
	struct match_set ms = {};
	struct port_range pr = {443, 443};

	ms.port_range = pr;
	ms.not = false;
	ms.type = MatchType_Port;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_udp_ipv6_dscp_conn_state")
int testcheck_lan_ingress_udp_ipv6_dscp_conn_state(struct __sk_buff *skb)
{
	return check_udp_conn_state_ipv6_udp_dscp(skb,
						  TC_ACT_REDIRECT,
						  0x20010db8, 0, 0, 0x10,
						  0x26064700, 0, 0, 0x1111,
						  24567, 443,
						  OUTBOUND_USER_DEFINED_MIN,
						  0, 10, true);
}

SEC("tc/pktgen/wan_egress_udp_first_fragment_listener")
int testpktgen_wan_egress_udp_first_fragment_listener(struct __sk_buff *skb)
{
	return set_ipv4_udp_first_fragment(skb,
					   IPV4(127,0,0,1), IPV4(8,8,4,4),
					   45678, 2053);
}

SEC("tc/setup/wan_egress_udp_first_fragment_listener")
int testsetup_wan_egress_udp_first_fragment_listener(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/wan_egress_udp_first_fragment_listener")
int testcheck_wan_egress_udp_first_fragment_listener(struct __sk_buff *skb)
{
	return check_redirect_with_listener_l4proto(skb, IPPROTO_UDP);
}

SEC("tc/pktgen/lan_ingress_udp_non_initial_fragment_passthrough")
int testpktgen_lan_ingress_udp_non_initial_fragment_passthrough(struct __sk_buff *skb)
{
	return set_ipv4_udp_non_initial_fragment(skb,
						 IPV4(192,168,0,1), IPV4(8,8,8,8));
}

SEC("tc/setup/lan_ingress_udp_non_initial_fragment_passthrough")
int testsetup_lan_ingress_udp_non_initial_fragment_passthrough(struct __sk_buff *skb)
{
	return do_tproxy_lan_ingress(skb, 14);
}

SEC("tc/check/lan_ingress_udp_non_initial_fragment_passthrough")
int testcheck_lan_ingress_udp_non_initial_fragment_passthrough(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_OK, 0);
}

SEC("tc/pktgen/wan_egress_udp_non_initial_fragment_passthrough")
int testpktgen_wan_egress_udp_non_initial_fragment_passthrough(struct __sk_buff *skb)
{
	return set_ipv4_udp_non_initial_fragment(skb,
						 IPV4(127,0,0,1), IPV4(8,8,4,4));
}

SEC("tc/setup/wan_egress_udp_non_initial_fragment_passthrough")
int testsetup_wan_egress_udp_non_initial_fragment_passthrough(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/wan_egress_udp_non_initial_fragment_passthrough")
int testcheck_wan_egress_udp_non_initial_fragment_passthrough(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, DAE_TC_CONTINUE, 0);
}

SEC("tc/pktgen/wan_egress_direct_mark_reroute")
int testpktgen_wan_egress_direct_mark_reroute(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,0,1), IPV4(9,9,9,9),
			    24567, 80);
}

SEC("tc/setup/wan_egress_direct_mark_reroute")
int testsetup_wan_egress_direct_mark_reroute(struct __sk_buff *skb)
{
	struct tuples_key key = {};
	struct tcphdr tcph = {};
	__u8 outbound = OUTBOUND_DIRECT;
	__u32 mark = TPROXY_MARK;
	__u8 must = 0;

	key.sip.u6_addr32[2] = bpf_htonl(0xffff);
	key.sip.u6_addr32[3] = bpf_htonl(IPV4(192,168,0,1));
	key.dip.u6_addr32[2] = bpf_htonl(0xffff);
	key.dip.u6_addr32[3] = bpf_htonl(IPV4(9,9,9,9));
	key.sport = bpf_htons(24567);
	key.dport = bpf_htons(80);
	key.l4proto = IPPROTO_TCP;
	tcph.syn = true;

	if (!mark_tcp_seen(&key, &tcph, false,
			   &outbound, &mark, &must, NULL,
			   0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN))
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

SEC("tc/check/wan_egress_direct_mark_reroute")
int testcheck_wan_egress_direct_mark_reroute(struct __sk_buff *skb)
{
	return check_tcp_conn_state_ipv4_tcp(skb,
					     TC_ACT_OK,
					     IPV4(192,168,0,1), IPV4(9,9,9,9),
					     24567, 80,
					     OUTBOUND_DIRECT,
					     TPROXY_MARK,
					     true);
}

SEC("tc/pktgen/conntrack_args_scratch_reset")
int testpktgen_conntrack_args_scratch_reset(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb,
			    IPV4(192,168,0,1), IPV4(1,1,1,1),
			    19233, 443);
}

SEC("tc/setup/conntrack_args_scratch_reset")
int testsetup_conntrack_args_scratch_reset(struct __sk_buff *skb)
{
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	__u32 mark = 0x12345678;
	__u8 must = 1;
	char pname[TASK_COMM_LEN] = "conntrack-test";
	struct conntrack_args *args =
		bpf_map_lookup_elem(&conntrack_args_map, &zero_key);

	if (!args)
		return TC_ACT_SHOT;

	conntrack_args_set(args, &outbound, &mark, &must, NULL, 11, pname, 99,
			   ROUTING_EPOCH_SLOT_UNKNOWN);
	conntrack_args_set(args, NULL, NULL, NULL, NULL, 0, NULL, 0,
			   ROUTING_EPOCH_SLOT_UNKNOWN);

	if (args->flags != 0) {
		bpf_printk("args->flags(%u) != 0\n", args->flags);
		return TC_ACT_SHOT;
	}
	if (args->dscp != 0) {
		bpf_printk("args->dscp(%u) != 0\n", args->dscp);
		return TC_ACT_SHOT;
	}
	if (args->flags & CT_ARGS_HAS_PNAME) {
		bpf_printk("args->flags reports a pname\n");
		return TC_ACT_SHOT;
	}
	for (int i = 0; i < TASK_COMM_LEN; i++) {
		if (args->pname[i] != 0) {
			bpf_printk("args->pname[%d](%u) != 0\n", i,
				   args->pname[i]);
			return TC_ACT_SHOT;
		}
	}
	if (args->pid != 0) {
		bpf_printk("args->pid(%u) != 0\n", args->pid);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

SEC("tc/check/conntrack_args_scratch_reset")
int testcheck_conntrack_args_scratch_reset(struct __sk_buff *skb)
{
	return check_status_and_mark(skb, TC_ACT_OK, 0);
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
				      DAE_TC_CONTINUE,
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
				      DAE_TC_CONTINUE,
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
				      DAE_TC_CONTINUE,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/dscp_match")
int testpktgen_dscp_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fastpath_with_dscp(skb,
					   IPV4(192,168,0,1), IPV4(1,1,1,1),
					   19233, 79, 4);
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

SEC("tc/pktgen/dscp_ipv6_match")
int testpktgen_dscp_ipv6_match(struct __sk_buff *skb)
{
	return set_ipv6_tcp_fastpath_with_dscp(skb,
					   0x20010db8, 0, 0, 0x10,
					   0x26064700, 0, 0, 0x1111,
					   19233, 79, 4);
}

SEC("tc/setup/dscp_ipv6_match")
int testsetup_dscp_ipv6_match(struct __sk_buff *skb)
{
	struct match_set ms = {};

	ms.dscp = 4;
	ms.not = false;
	ms.type = MatchType_Dscp;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dscp_ipv6_match")
int testcheck_dscp_ipv6_match(struct __sk_buff *skb)
{
	return check_routing_ipv6_tcp(skb,
				      TC_ACT_REDIRECT,
				      0x20010db8, 0, 0, 0x10,
				      0x26064700, 0, 0, 0x1111,
				      19233, 79);
}

SEC("tc/pktgen/dscp_mismatch")
int testpktgen_dscp_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fastpath_with_dscp(skb,
					   IPV4(192,168,0,1), IPV4(1,1,1,1),
					   19233, 79, 4);
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
				      DAE_TC_CONTINUE,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/dscp_ipv6_mismatch")
int testpktgen_dscp_ipv6_mismatch(struct __sk_buff *skb)
{
	return set_ipv6_tcp_fastpath_with_dscp(skb,
					   0x20010db8, 0, 0, 0x10,
					   0x26064700, 0, 0, 0x1111,
					   19233, 79, 4);
}

SEC("tc/setup/dscp_ipv6_mismatch")
int testsetup_dscp_ipv6_mismatch(struct __sk_buff *skb)
{
	struct match_set ms = {};

	ms.dscp = 5;
	ms.not = false;
	ms.type = MatchType_Dscp;
	ms.outbound = OUTBOUND_USER_DEFINED_MIN;
	ms.must = false;
	ms.mark = 0;
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	set_routing_fallback(OUTBOUND_DIRECT, true);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dscp_ipv6_mismatch")
int testcheck_dscp_ipv6_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv6_tcp(skb,
				      DAE_TC_CONTINUE,
				      0x20010db8, 0, 0, 0x10,
				      0x26064700, 0, 0, 0x1111,
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
				      DAE_TC_CONTINUE,
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
				      DAE_TC_CONTINUE,
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

struct ab_test_ah_hdr {
	__u8 nexthdr;
	__u8 payload_len;
	__be16 reserved;
	__be32 spi;
	__be32 seq_no;
};

SEC("tc/ab_test/control_plane_custom_mark")
int test_ab_control_plane_custom_mark(struct __sk_buff *skb)
{
	struct pid_pname *p = NULL;

	skb->mark = 0x100;
	if (pid_is_control_plane(skb, &p))
		return 1;

	skb->mark = 0x200;
	if (!pid_is_control_plane(skb, &p))
		return 2;

	skb->mark = 0x201;
	if (pid_is_control_plane(skb, &p))
		return 3;

	return 0;
}

SEC("tc/ab_test/ipv6_ah_udp_parse")
int test_ab_ipv6_ah_udp_parse(struct __sk_buff *skb)
{
	const __u32 packet_len = FAST_PATH_PACKET_SIZE;
	const __u32 ah_offset = ETH_HLEN + IP6_HLEN;
	const __u32 udp_offset = ah_offset + sizeof(struct ab_test_ah_hdr);

	if (bpf_skb_change_tail(skb, packet_len, 0))
		return 1;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + packet_len > data_end)
		return 2;

	struct ethhdr *eth = data;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	struct ab_test_ah_hdr *ah = data + ah_offset;
	struct udphdr *udp = data + udp_offset;

	eth->h_proto = bpf_htons(ETH_P_IPV6);
	set_ipv6_header_dscp(ip6, 0);
	ip6->payload_len = bpf_htons(packet_len - ETH_HLEN - IP6_HLEN);
	ip6->nexthdr = IPPROTO_AH;
	ip6->hop_limit = 64;
	ip6->saddr.in6_u.u6_addr32[3] = bpf_htonl(1);
	ip6->daddr.in6_u.u6_addr32[3] = bpf_htonl(2);

	ah->nexthdr = IPPROTO_UDP;
	ah->payload_len = 1;
	ah->spi = bpf_htonl(1);
	ah->seq_no = bpf_htonl(1);

	udp->source = bpf_htons(23456);
	udp->dest = bpf_htons(34567);
	udp->len = bpf_htons(packet_len - udp_offset);

	struct parse_transport_ctx *ctx =
		bpf_map_lookup_elem(&parse_ctx_scratch_map, &zero_key);
	if (!ctx)
		return 3;
	__builtin_memset(ctx, 0, sizeof(*ctx));

	if (parse_transport(skb, ETH_HLEN, ctx) != 0)
		return 4;
	if (ctx->l4proto != IPPROTO_UDP ||
	    ctx->listener_l4proto != IPPROTO_UDP)
		return 5;
	if (ctx->udph.source != bpf_htons(23456) ||
	    ctx->udph.dest != bpf_htons(34567))
		return 6;

	return 0;
}

#define AB_TEST_HOST_UDP_PORT 54321

SEC("tc/ab_test/lan_ingress_udp_host_listener_pktgen")
int test_ab_lan_ingress_udp_host_listener_pktgen(struct __sk_buff *skb)
{
	return set_ipv4_udp_fastpath_with_dscp(skb,
					   IPV4(192,168,0,1), IPV4(1,1,1,1),
					   24567, AB_TEST_HOST_UDP_PORT, 0);
}

SEC("tc/ab_test/lan_ingress_udp_host_listener")
int test_ab_lan_ingress_udp_host_listener(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, true);
	return do_tproxy_lan_ingress(skb, ETH_HLEN);
}

/* ---------------------------------------------------------------------------
 * D4 datapath visibility / robustness regression tests.
 *
 * Each program returns 0 on success and a distinct non-zero code on failure
 * (asserted by ab_regression_test.go). Counter assertions use deltas: all
 * ab_test programs share one loaded object, and therefore one bpf_stats_map.
 * Header bytes are written raw so the tests do not depend on the host's UAPI
 * bitfield layout.
 * ------------------------------------------------------------------------- */

static __always_inline int
ab_build_ipv4(struct __sk_buff *skb, __u8 proto, __u32 saddr, __u32 daddr,
	      __u16 frag_field, __u32 l4_len, struct iphdr **ip_out,
	      void **l4_out)
{
	__u32 packet_len = ETH_HLEN + IP4_HLEN + l4_len;
	struct ethhdr *eth;
	struct iphdr *ip;
	void *data, *data_end;

	if (bpf_skb_change_tail(skb, packet_len, 0))
		return 1;
	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	if (data + packet_len > data_end)
		return 2;
	eth = data;
	__builtin_memset(eth, 0, ETH_HLEN);
	eth->h_source[5] = 0xaa;
	eth->h_dest[5] = 0xbb;
	eth->h_proto = bpf_htons(ETH_P_IP);
	ip = data + ETH_HLEN;
	__builtin_memset(ip, 0, IP4_HLEN);
	/* version 4, ihl 5, written raw. */
	((__u8 *)ip)[0] = 0x45;
	ip->protocol = proto;
	ip->saddr = bpf_htonl(saddr);
	ip->daddr = bpf_htonl(daddr);
	ip->tot_len = bpf_htons(IP4_HLEN + l4_len);
	ip->frag_off = bpf_htons(frag_field);
	*ip_out = ip;
	*l4_out = data + ETH_HLEN + IP4_HLEN;
	return 0;
}

static __always_inline int
ab_build_ipv4_tcp(struct __sk_buff *skb, __u32 saddr, __u32 daddr,
		  __u16 sport, __u16 dport, __u8 doff, __u8 flags,
		  __u16 frag_field)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	void *l4;
	int ret;

	ret = ab_build_ipv4(skb, IPPROTO_TCP, saddr, daddr, frag_field, TCP_HLEN,
			    &ip, &l4);
	if (ret)
		return ret;
	tcp = l4;
	tcp->source = bpf_htons(sport);
	tcp->dest = bpf_htons(dport);
	/* data offset nibble and flags byte, written raw. */
	((__u8 *)tcp)[12] = doff << 4;
	((__u8 *)tcp)[13] = flags;
	return 0;
}

static __always_inline int
ab_build_ipv4_udp(struct __sk_buff *skb, __u32 saddr, __u32 daddr,
		  __u16 sport, __u16 dport, __u16 frag_field)
{
	struct iphdr *ip;
	struct udphdr *udp;
	void *l4;
	int ret;

	ret = ab_build_ipv4(skb, IPPROTO_UDP, saddr, daddr, frag_field,
			    sizeof(struct udphdr), &ip, &l4);
	if (ret)
		return ret;
	udp = l4;
	udp->source = bpf_htons(sport);
	udp->dest = bpf_htons(dport);
	udp->len = bpf_htons(sizeof(struct udphdr));
	return 0;
}

/*: the IP version/ihl and TCP doff/flags bytes must be read raw. */
SEC("tc/ab_test/raw_header_parse")
int test_ab_raw_header_parse(struct __sk_buff *skb)
{
	struct parse_transport_ctx *ctx;
	__u32 zero = 0;

	ctx = bpf_map_lookup_elem(&parse_ctx_scratch_map, &zero);
	if (!ctx)
		return 1;

	if (ab_build_ipv4_tcp(skb, IPV4(192, 168, 0, 1), IPV4(1, 1, 1, 1),
			      12345, 80, 5, TCPH_SYN, 0))
		return 2;
	__builtin_memset(ctx, 0, sizeof(*ctx));
	if (parse_transport(skb, ETH_HLEN, ctx) != 0)
		return 3;
	if (ctx->ihl != 5)
		return 4;
	if (ctx->l4proto != IPPROTO_TCP)
		return 5;
	if (ctx->listener_l4proto != IPPROTO_TCP)
		return 6;
	if (tcph_doff(&ctx->tcph) != 5)
		return 7;
	if (tcph_flags(&ctx->tcph) != TCPH_SYN)
		return 8;

	/* FIN|ACK is not a new connection. */
	if (ab_build_ipv4_tcp(skb, IPV4(192, 168, 0, 1), IPV4(1, 1, 1, 1),
			      12345, 80, 5, TCPH_FIN | TCPH_ACK, 0))
		return 9;
	__builtin_memset(ctx, 0, sizeof(*ctx));
	if (parse_transport(skb, ETH_HLEN, ctx) != 0)
		return 10;
	if (ctx->listener_l4proto != 0)
		return 11;
	if (tcph_flags(&ctx->tcph) != (TCPH_FIN | TCPH_ACK))
		return 12;
	return 0;
}

static __always_inline void
ab_redirect_key_ipv4(struct redirect_tuple *key, const struct tuples_key *five)
{
	__builtin_memset(key, 0, sizeof(*key));
	key->sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key->sip.u6_addr32[3] = five->sip.u6_addr32[3];
	key->dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key->dip.u6_addr32[3] = five->dip.u6_addr32[3];
}

/* +(a): the reply binding is single-writer while fresh, refreshed
 * in place by its own publisher, and rebindable once stale. */
SEC("tc/ab_test/redirect_rebind_lock")
int test_ab_redirect_rebind_lock(struct __sk_buff *skb)
{
	struct iphdr *ip;
	void *l4;
	struct tuples tuples = {};
	struct ethhdr publisher_a = {};
	struct ethhdr publisher_b = {};
	struct redirect_tuple key;
	struct redirect_entry *entry;
	__u64 before, after;

	if (ab_build_ipv4(skb, IPPROTO_TCP, IPV4(192, 168, 0, 1),
			  IPV4(8, 8, 8, 8), 0, TCP_HLEN, &ip, &l4))
		return 1;
	tuples.five.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	tuples.five.sip.u6_addr32[3] = ip->saddr;
	tuples.five.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	tuples.five.dip.u6_addr32[3] = ip->daddr;
	tuples.five.sport = bpf_htons(23456);
	tuples.five.dport = bpf_htons(443);
	tuples.five.l4proto = IPPROTO_TCP;
	publisher_a.h_source[5] = 0x11;
	publisher_b.h_source[5] = 0x22;
	ab_redirect_key_ipv4(&key, &tuples.five);

	/* 1) First publish of publisher A creates the binding. */
	if (publish_redirect_track_for_packet(skb, ETH_HLEN, &tuples,
					      &publisher_a, 0))
		return 2;
	entry = bpf_map_lookup_elem(&redirect_track, &key);
	if (!entry)
		return 3;
	if (entry->from_wan != 0 || entry->smac[5] != 0x11)
		return 4;

	/* 2) The same publisher only refreshes liveness, and must do so even
	 * for an entry that has gone stale (black-hole guard). */
	entry->last_seen_ns = bpf_ktime_get_ns() - 10000000000ULL;
	before = ab_read_stat(BPF_STATS_REDIRECT_REBIND_REJECTED);
	if (publish_redirect_track_for_packet(skb, ETH_HLEN, &tuples,
					      &publisher_a, 0))
		return 5;
	entry = bpf_map_lookup_elem(&redirect_track, &key);
	if (!entry)
		return 6;
	if (entry->from_wan != 0 || entry->smac[5] != 0x11)
		return 7;
	if (entry->last_seen_ns <= bpf_ktime_get_ns() - 10000000000ULL)
		return 8;
	if (ab_read_stat(BPF_STATS_REDIRECT_REBIND_REJECTED) != before)
		return 9;

	/* 3) A different publisher on a fresh binding is refused. */
	if (publish_redirect_track_for_packet(skb, ETH_HLEN, &tuples,
					      &publisher_b, 1))
		return 10;
	entry = bpf_map_lookup_elem(&redirect_track, &key);
	if (!entry)
		return 11;
	if (entry->from_wan != 0 || entry->smac[5] != 0x11)
		return 12;
	after = ab_read_stat(BPF_STATS_REDIRECT_REBIND_REJECTED);
	if (after != before + 1)
		return 13;

	/* 4) Once stale, the rebind is allowed (roaming client recovery). */
	entry->last_seen_ns = bpf_ktime_get_ns() -
			      (EVENT_RATE.redirect_rebind_stale_ns +
			       1000000000ULL);
	if (publish_redirect_track_for_packet(skb, ETH_HLEN, &tuples,
					      &publisher_b, 1))
		return 14;
	entry = bpf_map_lookup_elem(&redirect_track, &key);
	if (!entry)
		return 15;
	if (entry->from_wan != 1 || entry->smac[5] != 0x22)
		return 16;
	if (ab_read_stat(BPF_STATS_REDIRECT_REBIND_REJECTED) != after)
		return 17;
	return 0;
}

/* Marks a pure SYN on `key`. `syn_epoch_slot` is the epoch the SYN is routed
 * under (the value route() would pack into its result), so a probe can present
 * the same flow across an epoch cutover. */
static __always_inline int
ab_mark_syn(struct tuples_key *key, bool with_routing, __u8 outbound,
	    __u32 mark, __u8 syn_epoch_slot)
{
	struct tcphdr tcp = {};
	__u8 out = outbound;
	__u32 mk = mark;
	__u8 must = 0;

	((__u8 *)&tcp)[12] = 5 << 4;
	((__u8 *)&tcp)[13] = TCPH_SYN;
	if (!with_routing)
		return mark_tcp_seen(key, &tcp, false, NULL, NULL, NULL, NULL,
				     0, NULL, 0,
				     ROUTING_EPOCH_SLOT_UNKNOWN) ? 0 : 1;
	return mark_tcp_seen(key, &tcp, false, &out, &mk, &must, NULL, 0, NULL,
			     0, syn_epoch_slot) ? 0 : 1;
}

/*: a same-tuple pure SYN must not rewrite a live ACTIVE flow's routing
 * metadata, but must still refresh its liveness. */
SEC("tc/ab_test/syn_rebind_lock")
int test_ab_syn_rebind_lock(struct __sk_buff *skb)
{
	struct tuples_key key = {};
	struct conn_state *state;
	__u64 before;

	key.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key.sip.u6_addr32[3] = bpf_htonl(IPV4(10, 0, 0, 1));
	key.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key.dip.u6_addr32[3] = bpf_htonl(IPV4(10, 0, 0, 2));
	key.sport = bpf_htons(40000);
	key.dport = bpf_htons(80);
	key.l4proto = IPPROTO_TCP;

	/* 1) A first routed SYN opens the live flow. */
	if (ab_mark_syn(&key, true, OUTBOUND_USER_DEFINED_MIN, 0x11,
			routing_epoch_slot_encode(0)))
		return 1;
	state = bpf_map_lookup_elem(&conn_state_map, &key);
	if (!state || state->state != TCP_STATE_ACTIVE ||
	    !state->meta.data.has_routing ||
	    state->meta.data.outbound != OUTBOUND_USER_DEFINED_MIN)
		return 2;

	state->last_seen_ns = bpf_ktime_get_ns() - 10000000000ULL;
	before = ab_read_stat(BPF_STATS_SYN_REBIND_REJECTED);

	/* 2) A competing SYN of the same epoch must be refused, without
	 * freezing liveness. */
	if (ab_mark_syn(&key, true, OUTBOUND_USER_DEFINED_MIN + 1, 0x22,
			routing_epoch_slot_encode(0)))
		return 3;
	state = bpf_map_lookup_elem(&conn_state_map, &key);
	if (!state)
		return 4;
	if (!state->meta.data.has_routing)
		return 5;
	if (state->meta.data.outbound != OUTBOUND_USER_DEFINED_MIN ||
	    state->meta.data.mark != 0x11)
		return 6;
	if (state->state != TCP_STATE_ACTIVE)
		return 7;
	if (state->last_seen_ns <= bpf_ktime_get_ns() - 10000000000ULL)
		return 8;
	if (ab_read_stat(BPF_STATS_SYN_REBIND_REJECTED) != before + 1)
		return 9;

	/* 3) A routingless entry is still replaceable (historical behavior). */
	if (bpf_map_delete_elem(&conn_state_map, &key))
		return 10;
	if (ab_mark_syn(&key, false, 0, 0, ROUTING_EPOCH_SLOT_UNKNOWN))
		return 11;
	state = bpf_map_lookup_elem(&conn_state_map, &key);
	if (!state || state->meta.data.has_routing)
		return 12;
	if (ab_mark_syn(&key, true, OUTBOUND_USER_DEFINED_MIN + 1, 0x22,
			routing_epoch_slot_encode(0)))
		return 13;
	state = bpf_map_lookup_elem(&conn_state_map, &key);
	if (!state || !state->meta.data.has_routing ||
	    state->meta.data.outbound != OUTBOUND_USER_DEFINED_MIN + 1)
		return 14;
	if (ab_read_stat(BPF_STATS_SYN_REBIND_REJECTED) != before + 1)
		return 15;
	return 0;
}

/* Builds the flow key used by the rebind probes below. */
static __always_inline void
ab_rebind_key(struct tuples_key *key, __u16 sport)
{
	key->sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key->sip.u6_addr32[3] = bpf_htonl(IPV4(10, 0, 0, 1));
	key->dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key->dip.u6_addr32[3] = bpf_htonl(IPV4(10, 0, 0, 2));
	key->sport = bpf_htons(sport);
	key->dport = bpf_htons(80);
	key->l4proto = IPPROTO_TCP;
}

/* Stages one routing rule in each epoch and publishes `active_slot` as the
 * current one: the cutover a reload performs after the new generation's rules
 * and metadata are in place. */
static __always_inline int
ab_stage_two_epochs(__u32 active_slot)
{
	__u32 zero = 0;

	if (set_routing_epoch_port_rule(0, 443, OUTBOUND_USER_DEFINED_MIN))
		return 1;
	if (set_routing_epoch_port_rule(1, 443, OUTBOUND_USER_DEFINED_MIN + 1))
		return 2;
	return bpf_map_update_elem(&active_routing_epoch_map, &zero,
				   &active_slot, BPF_ANY) ? 3 : 0;
}

/* Routing epoch semantics on a pure SYN that reuses a live flow's tuple.
 *
 * `entry_slot` is the epoch the live entry was routed under, `syn_epoch_slot`
 * is the epoch the current SYN is routed under, and `final_slot` is the epoch
 * the entry must carry afterwards.
 *
 * Same epoch: the lock keeps the flow's routing untouched and counts the
  * refusal . Different epoch: the entry is dropped and re-created from
 * the current epoch's decision, and counted as re-routed - "after the rules
 * changed, a new connection uses the new rules" - with no comparison of the
 * two decisions anywhere in the datapath.
 */
static __always_inline int
ab_syn_epoch_case(__u32 entry_slot, __u32 syn_epoch_slot, __u32 final_slot)
{
	struct tuples_key key = {};
	struct conn_state *state;
	__u8 expected_outbound;
	__u64 rejected_before, rerouted_before;

	if (entry_slot >= ROUTING_EPOCH_SLOT_NUM ||
	    syn_epoch_slot >= ROUTING_EPOCH_SLOT_NUM ||
	    final_slot >= ROUTING_EPOCH_SLOT_NUM)
		return 1;
	expected_outbound = final_slot == 0 ? OUTBOUND_USER_DEFINED_MIN :
					      OUTBOUND_USER_DEFINED_MIN + 1;

	ab_rebind_key(&key, 40001);

	/* 1) Open a live routed flow in the entry's epoch. */
	if (ab_mark_syn(&key, true,
			entry_slot == 0 ? OUTBOUND_USER_DEFINED_MIN :
					  OUTBOUND_USER_DEFINED_MIN + 1,
			0x11, routing_epoch_slot_encode(entry_slot)))
		return 3;
	state = bpf_map_lookup_elem(&conn_state_map, &key);
	if (!state || state->state != TCP_STATE_ACTIVE ||
	    !state->meta.data.has_routing ||
	    state->routing_epoch_slot != routing_epoch_slot_encode(entry_slot))
		return 4;

	state->last_seen_ns = bpf_ktime_get_ns() - 10000000000ULL;
	rejected_before = ab_read_stat(BPF_STATS_SYN_REBIND_REJECTED);
	rerouted_before =
		ab_read_stat(BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE);

	if (ab_stage_two_epochs(syn_epoch_slot))
		return 5;

	/* 2) The same tuple opens again under the SYN's epoch. Its decision is
	 * what that epoch's staged rule produces, so a re-route is visible as
	 * the SYN epoch's outbound. */
	if (ab_mark_syn(&key, true, expected_outbound, 0x22,
			routing_epoch_slot_encode(syn_epoch_slot)))
		return 6;
	state = bpf_map_lookup_elem(&conn_state_map, &key);
	if (!state || state->state != TCP_STATE_ACTIVE ||
	    !state->meta.data.has_routing)
		return 7;
	if (state->routing_epoch_slot != routing_epoch_slot_encode(final_slot))
		return 8;

	if (entry_slot == syn_epoch_slot) {
		/* Same epoch: locked. Routing, mark and liveness stay the flow's
		 * own, and the re-route counter must not move. */
		if (state->meta.data.outbound != OUTBOUND_USER_DEFINED_MIN ||
		    state->meta.data.mark != 0x11)
			return 9;
		if (state->last_seen_ns <= bpf_ktime_get_ns() - 10000000000ULL)
			return 10;
		if (ab_read_stat(BPF_STATS_SYN_REBIND_REJECTED) !=
		    rejected_before + 1)
			return 11;
		if (ab_read_stat(
			    BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE) !=
		    rerouted_before)
			return 12;
	} else {
		/* Changed epoch: re-routed onto the new decision, and the
		 * refusal counter must not move. */
		if (state->meta.data.outbound != expected_outbound ||
		    state->meta.data.mark != 0x22)
			return 13;
		if (state->datapath_generation != PARAM.datapath_generation)
			return 14;
		if (ab_read_stat(BPF_STATS_SYN_REBIND_REJECTED) !=
		    rejected_before)
			return 15;
		if (ab_read_stat(
			    BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE) !=
		    rerouted_before + 1)
			return 16;
	}
	return 0;
}

/* Task 1: a live flow's cached routing is only inherited inside its own
 * routing epoch. A reload cutover to the other slot must re-route the next
 * SYN, in both directions, while a same-epoch SYN stays locked. */
SEC("tc/ab_test/syn_rebind_epoch_change")
int test_ab_syn_rebind_epoch_change(struct __sk_buff *skb)
{
	int ret;

	(void)skb;
		/* Same epoch (entry slot 0, SYN on slot 0): still locked . */
	ret = ab_syn_epoch_case(0, 0, 0);
	if (ret)
		return ret;

	/* Slot 0 to slot 1: the new epoch's decision must win. */
	ret = ab_syn_epoch_case(0, 1, 1);
	if (ret)
		return 20 + ret;

	/* Slot 1 to slot 0: the same rule holds in the other direction. */
	ret = ab_syn_epoch_case(1, 0, 0);
	if (ret)
		return 40 + ret;
	return 0;
}

/* Task 1: the datapath generation is part of the generation identity. An entry
 * written by another datapath (pinned conn_state_map across a restart or an
 * upgrade) is not inherited even when the routing epoch number matches. */
SEC("tc/ab_test/syn_rebind_generation_change")
int test_ab_syn_rebind_generation_change(struct __sk_buff *skb)
{
	struct tuples_key key = {};
	struct conn_state *state;
	__u64 rejected_before, rerouted_before;
	__u16 foreign_generation = PARAM.datapath_generation + 1;

	(void)skb;
	if (foreign_generation == 0)
		return 1;
	if (ab_stage_two_epochs(0))
		return 2;

	ab_rebind_key(&key, 40002);
	/* 1) A live flow of the current datapath, same epoch: locked. */
	if (ab_mark_syn(&key, true, OUTBOUND_USER_DEFINED_MIN, 0x11,
			routing_epoch_slot_encode(0)))
		return 3;
	state = bpf_map_lookup_elem(&conn_state_map, &key);
	if (!state || state->datapath_generation != PARAM.datapath_generation)
		return 4;
	state->last_seen_ns = bpf_ktime_get_ns() - 10000000000ULL;
	rejected_before = ab_read_stat(BPF_STATS_SYN_REBIND_REJECTED);
	rerouted_before =
		ab_read_stat(BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE);
	if (ab_mark_syn(&key, true, OUTBOUND_USER_DEFINED_MIN + 1, 0x22,
			routing_epoch_slot_encode(0)))
		return 5;
	state = bpf_map_lookup_elem(&conn_state_map, &key);
	if (!state || state->meta.data.outbound != OUTBOUND_USER_DEFINED_MIN ||
	    state->meta.data.mark != 0x11)
		return 6;
	if (ab_read_stat(BPF_STATS_SYN_REBIND_REJECTED) != rejected_before + 1)
		return 7;

	/* 2) Same tuple, same epoch number, but the entry belongs to another
	 * datapath: the cached routing must be replaced. */
	state->datapath_generation = foreign_generation;
	if (ab_mark_syn(&key, true, OUTBOUND_USER_DEFINED_MIN + 1, 0x22,
			routing_epoch_slot_encode(0)))
		return 8;
	state = bpf_map_lookup_elem(&conn_state_map, &key);
	if (!state)
		return 9;
	if (state->meta.data.outbound != OUTBOUND_USER_DEFINED_MIN + 1 ||
	    state->meta.data.mark != 0x22 ||
	    state->routing_epoch_slot != routing_epoch_slot_encode(0))
		return 10;
	if (state->datapath_generation != PARAM.datapath_generation)
		return 11;
	if (ab_read_stat(BPF_STATS_SYN_REBIND_REJECTED) != rejected_before + 1)
		return 12;
	if (ab_read_stat(BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE) !=
	    rerouted_before + 1)
		return 13;
	return 0;
}

/* Task 2: the reply path only refreshes a binding's lease for its own
 * publisher. A different publisher's reply must not extend the window that
 * keeps it out, otherwise the rejected side re-freezes the entry for as long
 * as it keeps replying. */
SEC("tc/ab_test/redirect_reply_refresh_publisher")
int test_ab_redirect_reply_refresh_publisher(struct __sk_buff *skb)
{
	struct tuples tuples = {};
	struct ethhdr winner = {};
	struct redirect_tuple key;
	struct redirect_entry *entry;
	__u64 mtime;

	if (ab_build_ipv4_tcp(skb, IPV4(192, 168, 0, 1), IPV4(8, 8, 8, 8),
			      12345, 443, 5, TCPH_SYN, 0))
		return 1;
	tuples.five.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	tuples.five.sip.u6_addr32[3] = bpf_htonl(IPV4(192, 168, 0, 1));
	tuples.five.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	tuples.five.dip.u6_addr32[3] = bpf_htonl(IPV4(8, 8, 8, 8));
	tuples.five.sport = bpf_htons(12345);
	tuples.five.dport = bpf_htons(443);
	tuples.five.l4proto = IPPROTO_TCP;
	winner.h_source[5] = 0xaa;
	winner.h_dest[5] = 0xbb;
	ab_redirect_key_ipv4(&key, &tuples.five);

	/* Start from a clean binding: this probe shares its object (and thus its
	 * redirect_track map) with the reply-rebind probe above, whose leftover
	 * entry for this key is deliberately frozen against another publisher. */
	bpf_map_delete_elem(&redirect_track, &key);

	/* The reply-path binding as the winning publisher created it. */
	if (publish_redirect_track_for_packet(skb, ETH_HLEN, &tuples, &winner,
					      0))
		return 2;
	entry = bpf_map_lookup_elem(&redirect_track, &key);
	if (!entry || entry->smac[5] != 0xaa || entry->dmac[5] != 0xbb)
		return 3;

	/* Set a stale lease so any refresh is unambiguous: the binding is due
	 * for takeover as soon as the forward path sees it. */
	entry->last_seen_ns = bpf_ktime_get_ns() - 10000000000ULL;
	mtime = entry->last_seen_ns;

	/* The owner is recognized from the reply packet, and only the owner is. */
	if (ab_build_ipv4_tcp(skb, IPV4(8, 8, 8, 8), IPV4(192, 168, 0, 1),
			      443, 12345, 5, TCPH_ACK, 0))
		return 4;
	if (ab_store_l2_addrs(skb, 0xaa, 0xbb))
		return 5;
	entry = bpf_map_lookup_elem(&redirect_track, &key);
	if (!entry)
		return 6;
	if (!reply_publisher_matches(skb, entry))
		return 7;

	/* The reply-path hook needs the L2 header inside its linear region
	 * (load_redirect_tuple pulls REDIRECT_PULL_SIZE); pad the frame past
	 * that, as a real reply frame carrying payload would be. */
	if (bpf_skb_change_tail(skb, REDIRECT_PULL_SIZE, 0))
		return 8;

	/* A reply from a different publisher: the tuple matches, so it is still
	 * redirected toward the binding's owner, but the lease is not extended.
	 * Before the fix this refresh ran unconditionally, so the rejected side
	 * re-froze the binding with every reply it sent and the window that is
	 * supposed to hand the flow over never elapsed. */
	if (ab_store_l2_addrs(skb, 0xcc, 0xdd))
		return 9;
	entry = bpf_map_lookup_elem(&redirect_track, &key);
	if (!entry)
		return 10;
	if (reply_publisher_matches(skb, entry))
		return 11;
	tproxy_dae0_ingress(skb);
	entry = bpf_map_lookup_elem(&redirect_track, &key);
	if (!entry)
		return 12;
	if (entry->last_seen_ns != mtime)
		return 13;
	if (entry->smac[5] != 0xaa)
		return 14;

	/* The owner's own reply still refreshes the lease, so an active winner
	 * keeps its binding while a silent one lets the window lapse and the
	 * stale entry becomes rebindable on the forward path. */
	if (ab_store_l2_addrs(skb, 0xaa, 0xbb))
		return 15;
	entry = bpf_map_lookup_elem(&redirect_track, &key);
	if (!entry)
		return 16;
	if (!reply_publisher_matches(skb, entry))
		return 17;
	tproxy_dae0_ingress(skb);
	entry = bpf_map_lookup_elem(&redirect_track, &key);
	if (!entry)
		return 18;
	if (entry->last_seen_ns <= mtime)
		return 19;
	if (entry->last_seen_ns < bpf_ktime_get_ns() - 1000000000ULL)
		return 20;
	return 0;
}

/* Number of packets the stateless-passthrough and fragment-tail bursts below
 * push through the datapath. Large enough that an unthrottled per-event
 * emission could not hide behind the 1s rate window of a single emission. */
#define AB_PASSTHROUGH_BURST_PACKETS 8

/* Clears a reserved event rate slot and proves it stays clear afterwards.
 * The slot is the only witness a userspace consumer would ever see: an
 * emission must first claim it through blocked_event_rate_limited(), which
 * overwrites it with the current monotonic time. A slot written to zero is
 * always outside the 1s window on a host that has been up for more than a
 * second, so a single emission would leave a non-zero timestamp behind. */
static __always_inline bool ab_rate_slot_armed_at_zero(__u32 key)
{
	__u64 zero = 0;

	if (bpf_map_update_elem(&alive_block_rate_map, &key, &zero, BPF_ANY))
		return false;
	return true;
}

static __always_inline bool ab_rate_slot_is_untouched(__u32 key)
{
	__u64 *slot = bpf_map_lookup_elem(&alive_block_rate_map, &key);

	return slot && *slot == 0;
}

/*: an established TCP packet with no cached routing is forwarded (policy
 * unchanged) and counted per packet. A burst of packets must therefore count
 * exactly one per packet and emit no event at all: the event this path used to
 * emit shared one 1s budget across every affected flow, so the normal steady
 * state (what every pre-existing flow does after a restart) produced one
 * warning per second for as long as the flows lived. Its upper bound is 0. */
SEC("tc/ab_test/stateless_tcp_passthrough")
int test_ab_stateless_tcp_passthrough(struct __sk_buff *skb)
{
	__u32 key = EVENT_RATE.stateless_tcp_key;
	__u64 before;
	int i;

	if (!ab_rate_slot_armed_at_zero(key))
		return 1;

	before = ab_read_stat(BPF_STATS_STATELESS_TCP_PASSTHROUGH);
	for (i = 0; i < AB_PASSTHROUGH_BURST_PACKETS; i++) {
		if (ab_build_ipv4_tcp(skb, IPV4(192, 168, 1, 1),
				      IPV4(5, 5, 5, 5), 33333, 443, 5, TCPH_ACK, 0))
			return 2;
		if (do_tproxy_lan_ingress(skb, ETH_HLEN) != TC_ACT_OK)
			return 3;
	}
	/* Counter exactness: one increment per packet, no more and no less. */
	if (ab_read_stat(BPF_STATS_STATELESS_TCP_PASSTHROUGH) !=
	    before + AB_PASSTHROUGH_BURST_PACKETS)
		return 4;
	/* The event bound is zero: no packet of the burst emitted anything. */
	if (!ab_rate_slot_is_untouched(key))
		return 5;
	return 0;
}

/* (decision A20): an unsolicited WAN-ingress UDP flow is COUNTED but
 * still tracked. Creating the entry is what carries the
 * is_wan_ingress_direction marker that host-terminated UDP replies rely on, so
 * the counter is observability, not enforcement. A flow that already has state
 * is not counted. */
SEC("tc/ab_test/unsolicited_udp_wan_ingress")
int test_ab_unsolicited_udp_wan_ingress(struct __sk_buff *skb)
{
	struct tuples_key reversed = {};
	struct conn_state *state;
	__u64 before, after;

	if (ab_build_ipv4_udp(skb, IPV4(203, 0, 113, 9), IPV4(192, 168, 1, 50),
			      40000, 50000, 0))
		return 1;
	/* The key the WAN-ingress refresh would have written. */
	reversed.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	reversed.sip.u6_addr32[3] = bpf_htonl(IPV4(192, 168, 1, 50));
	reversed.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	reversed.dip.u6_addr32[3] = bpf_htonl(IPV4(203, 0, 113, 9));
	reversed.sport = bpf_htons(50000);
	reversed.dport = bpf_htons(40000);
	reversed.l4proto = IPPROTO_UDP;

	/* Cleanup only: the key is expected to be absent. */
	if (bpf_map_lookup_elem(&conn_state_map, &reversed))
		bpf_map_delete_elem(&conn_state_map, &reversed);

	before = ab_read_stat(BPF_STATS_UNSOLICITED_UDP_SEEN);
	if (do_tproxy_wan_ingress(skb, ETH_HLEN) != DAE_TC_CONTINUE)
		return 3;
	after = ab_read_stat(BPF_STATS_UNSOLICITED_UDP_SEEN);
	if (after != before + 1)
		return 4;
	/* The flow is still tracked, marker included: no state was refused. */
	state = bpf_map_lookup_elem(&conn_state_map, &reversed);
	if (!state || !state->is_wan_ingress_direction)
		return 5;

	/* A packet of a flow that already has state is not counted. */
	if (do_tproxy_wan_ingress(skb, ETH_HLEN) != DAE_TC_CONTINUE)
		return 6;
	if (ab_read_stat(BPF_STATS_UNSOLICITED_UDP_SEEN) != after)
		return 7;
	state = bpf_map_lookup_elem(&conn_state_map, &reversed);
	if (!state || !state->is_wan_ingress_direction)
		return 8;
	return 0;
}

/*: a non-initial fragment is still forwarded and counted per packet, with
 * no per-event emission: forwarding it is the intended policy, and the tuple
 * such an event could carry has no L4 header to read (the parser returns
 * before L4 parsing), so it reported scratch ports rather than wire data. */
SEC("tc/ab_test/frag_tail_passthrough")
int test_ab_frag_tail_passthrough(struct __sk_buff *skb)
{
	__u32 key = EVENT_RATE.frag_tail_key;
	__u64 before;
	int i;

	if (!ab_rate_slot_armed_at_zero(key))
		return 1;

	before = ab_read_stat(BPF_STATS_FRAG_TAIL_PASSED);
	for (i = 0; i < AB_PASSTHROUGH_BURST_PACKETS; i++) {
		/* Fragment offset 1 (8 bytes): non-initial. */
		if (ab_build_ipv4_udp(skb, IPV4(192, 168, 2, 1),
				      IPV4(9, 9, 9, 9), 34567, 4500, 1))
			return 2;
		if (do_tproxy_lan_ingress(skb, ETH_HLEN) != TC_ACT_OK)
			return 3;
	}
	if (ab_read_stat(BPF_STATS_FRAG_TAIL_PASSED) !=
	    before + AB_PASSTHROUGH_BURST_PACKETS)
		return 4;
	if (!ab_rate_slot_is_untouched(key))
		return 5;
	return 0;
}

/*: "the IP header parsed but the L4 protocol is not routed" and "this is
 * not an IP frame" are distinct return codes, and the first one is counted at
 * the consumer without changing its decision. */
SEC("tc/ab_test/parse_return_code_split")
int test_ab_parse_return_code_split(struct __sk_buff *skb)
{
	struct parse_transport_ctx *ctx;
	struct ethhdr *eth;
	void *data, *data_end;
	struct iphdr *ip;
	void *l4;
	__u32 zero = 0;
	__u64 before;

	ctx = bpf_map_lookup_elem(&parse_ctx_scratch_map, &zero);
	if (!ctx)
		return 1;

	/* IP header, L4 protocol 47 (GRE). */
	if (ab_build_ipv4(skb, IPPROTO_GRE, IPV4(192, 168, 3, 1),
			  IPV4(7, 7, 7, 7), 0, 8, &ip, &l4))
		return 2;
	__builtin_memset(ctx, 0, sizeof(*ctx));
	if (parse_transport(skb, ETH_HLEN, ctx) != PARSE_UNSUPPORTED_L4)
		return 3;

	/* ARP: no IP header at all. */
	if (bpf_skb_change_tail(skb, ETH_HLEN, 0))
		return 4;
	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	if (data + ETH_HLEN > data_end)
		return 5;
	eth = data;
	__builtin_memset(eth, 0, ETH_HLEN);
	eth->h_proto = bpf_htons(ETH_P_ARP);
	__builtin_memset(ctx, 0, sizeof(*ctx));
	if (parse_transport(skb, ETH_HLEN, ctx) != PARSE_UNSUPPORTED_ETH)
		return 6;

	/* The consumer counts the L4 case and still forwards. */
	if (ab_build_ipv4(skb, IPPROTO_GRE, IPV4(192, 168, 3, 1),
			  IPV4(7, 7, 7, 7), 0, 8, &ip, &l4))
		return 7;
	before = ab_read_stat(BPF_STATS_PARSE_UNSUPPORTED_L4);
	if (do_tproxy_lan_ingress(skb, ETH_HLEN) != TC_ACT_OK)
		return 8;
	if (ab_read_stat(BPF_STATS_PARSE_UNSUPPORTED_L4) != before + 1)
		return 9;
	return 0;
}

/*(c): with no so_mark injected the reserved-bit test is the last-resort
 * fallback, and it is counted. */
SEC("tc/ab_test/control_plane_sockmark_fallback")
int test_ab_control_plane_sockmark_fallback(struct __sk_buff *skb)
{
	struct pid_pname *p = NULL;
	__u64 before;

	before = ab_read_stat(BPF_STATS_SOCKMARK_FALLBACK);
	skb->mark = 0x101;
	if (!pid_is_control_plane(skb, &p))
		return 1;
	if (ab_read_stat(BPF_STATS_SOCKMARK_FALLBACK) != before + 1)
		return 2;
	skb->mark = 0x200;
	if (pid_is_control_plane(skb, &p))
		return 3;
	return 0;
}

SEC("tc/ab_test/udp_refresh_bypasses_routing_args")
int test_ab_udp_refresh_bypasses_routing_args(struct __sk_buff *skb)
{
	struct tuples_key key = {};
	struct conntrack_args *args;
	struct conn_state *state;
	__u8 outbound = OUTBOUND_USER_DEFINED_MIN;
	__u8 must = 1;
	__u32 mark = 0x12345678;
	__u8 status = UDP_CONN_STATE_STATUS_UNAVAILABLE;

	key.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key.sip.u6_addr32[3] = bpf_htonl(IPV4(192,168,40,1));
	key.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
	key.dip.u6_addr32[3] = bpf_htonl(IPV4(10,40,0,1));
	key.sport = bpf_htons(44001);
	key.dport = bpf_htons(8443);
	key.l4proto = IPPROTO_UDP;
	bpf_map_delete_elem(&conn_state_map, &key);

	args = bpf_map_lookup_elem(&conntrack_args_map, &zero_key);
	if (!args)
		return 1;
	conntrack_args_set(args, &outbound, &mark, &must, NULL, 0, NULL, 0,
			   ROUTING_EPOCH_SLOT_UNKNOWN);

	state = mark_udp_seen_with_status(&key, false, NULL, NULL, NULL, NULL,
					  0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN,
					  &status);
	if (!state || status != UDP_CONN_STATE_STATUS_CREATED)
		return 2;
	if (state->meta.data.has_routing || state->meta.data.outbound ||
	    state->meta.data.mark || state->meta.data.must)
		return 3;

	bpf_map_delete_elem(&conn_state_map, &key);
	return 0;
}

SEC("tc/ab_test/cookie_pid_lazy_refresh")
int test_ab_cookie_pid_lazy_refresh(struct __sk_buff *skb)
{
	struct pid_pname entry = {};
	struct pid_pname *mapped = NULL;
	__u64 cookie = bpf_get_socket_cookie(skb);
	__u64 now = bpf_ktime_get_ns();
	__u64 stale = now - COOKIE_PID_UPDATE_INTERVAL_NS - 1;

	entry.last_seen_ns = now;
	if (bpf_map_update_elem(&cookie_pid_map, &cookie, &entry, BPF_ANY))
		return 1;
	pid_is_control_plane(skb, &mapped);
	if (!mapped || mapped->last_seen_ns != now)
		return 2;

	mapped->last_seen_ns = stale;
	pid_is_control_plane(skb, &mapped);
	if (!mapped || mapped->last_seen_ns <= stale)
		return 3;

	bpf_map_delete_elem(&cookie_pid_map, &cookie);
	return 0;
}
