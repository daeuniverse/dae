// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>

//go:build exclude

#define __DEBUG

#include "../tproxy.c"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map SEC(".maps") = {
	.values = {
		[0] = &tproxy_dae0peer_ingress,
	},
};

SEC("tc/pktgen/0")
int testpktgen_0(struct __sk_buff *skb)
{
	// set l2 header
	bpf_skb_change_tail(skb, 14, 0);
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	eth->h_proto = 0x0800;
	eth->h_source[0] = 0x0a;
	eth->h_dest[5] = 0x0b;
	return TC_ACT_OK;
}

SEC("tc/setup/0")
int testsetup_0(struct __sk_buff *skb)
{
	skb->cb[0] = TPROXY_MARK;
	skb->cb[1] = IPPROTO_TCP;
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/0")
int testcheck_0(struct __sk_buff *skb)
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
		bpf_printk("status_code != TC_ACT_OK\n");
		return TC_ACT_SHOT;
	}

	struct ethhdr *eth = data + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (eth->h_proto != 0x0800) {
		bpf_printk("eth->h_proto != 0x0800\n");
		return TC_ACT_SHOT;
	}
	if (eth->h_source[0] != 0x0a) {
		bpf_printk("eth->h_source[0] != 0x0a\n");
		return TC_ACT_SHOT;
	}
	if (eth->h_dest[5] != 0x0b) {
		bpf_printk("eth->h_dest[5] != 0x0b\n");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}
