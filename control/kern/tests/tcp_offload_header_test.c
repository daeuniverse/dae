// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

//go:build ignore

/* Native replay of the production helpers; only kernel memory reads are mocked. */
#include <linux/types.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST_BIG_ENDIAN
#undef __BYTE_ORDER__
#define __BYTE_ORDER__ __ORDER_BIG_ENDIAN__
#endif
#include "../headers/bpf_endian.h"

#define IPV6_BYTE_LENGTH 16

union ip6 {
	__u8 u6_addr8[16];
	__be32 u6_addr32[4];
};

struct tuples_key {
	union ip6 sip;
	union ip6 dip;
	__be16 sport;
	__be16 dport;
	__u8 l4proto;
	__u8 pad[3];
};

struct sk_buff {
	unsigned char *head;
	__u32 tail;
	__u16 network_header;
	__u16 transport_header;
};

static unsigned char packet[512];
static bool fail_read;

#define BPF_CORE_READ(skb, field) ((skb)->field)
#define BPF_CORE_READ_INTO(dst, skb, field) \
	(fail_read ? -1 : (*(dst) = (skb)->field, 0))

static int bpf_probe_read_kernel(void *dst, __u32 size, const void *src)
{
	uintptr_t addr = (uintptr_t)src;
	uintptr_t base = (uintptr_t)packet;

	if (fail_read || addr < base || addr > base + sizeof(packet) ||
	    size > base + sizeof(packet) - addr)
		return -1;
	memcpy(dst, src, size);
	return 0;
}

#include "../include/tcp_offload.h"

static void require(bool ok, const char *message)
{
	if (!ok) {
		fprintf(stderr, "%s\n", message);
		exit(1);
	}
}

static void check_ports(void)
{
	__u32 port;

	for (port = 0; port <= 65535; port++) {
#ifdef TEST_BIG_ENDIAN
		__u32 remote = port;
		__be16 expected = port;
#else
		__u32 remote = (__u32)__builtin_bswap16(port) << 16;
		__be16 expected = __builtin_bswap16(port);
#endif

		require(tcp_offload_remote_port(remote) == expected,
			"remote_port ABI mismatch");
	}
}

static struct sk_buff fixture(bool ipv6, __u8 nexthdr, __u16 extra)
{
	struct sk_buff skb = {
		.head = packet,
		.network_header = 32,
		.transport_header = 32 + (ipv6 ? 40 : 20) + extra,
	};
	unsigned char *ip = packet + skb.network_header;
	unsigned char *tcp = packet + skb.transport_header;

	memset(packet, 0, sizeof(packet));
	ip[0] = ipv6 ? 0x60 : 0x45 + extra / 4;
	if (ipv6) {
		ip[6] = nexthdr;
		ip[8] = 0x20;
		ip[9] = 0x01;
		ip[23] = 1;
		ip[24] = 0x20;
		ip[25] = 0x01;
		ip[39] = 2;
	} else {
		ip[9] = IPPROTO_TCP;
		ip[12] = 127;
		ip[15] = 1;
		ip[16] = 127;
		ip[19] = 2;
	}
	if (ipv6 && extra) {
		ip[40] = IPPROTO_TCP;
		ip[41] = extra / 8 - 1;
	}
	tcp[0] = 0x30;
	tcp[1] = 0x39;
	tcp[2] = 0x01;
	tcp[3] = 0xbb;
	tcp[12] = 0x50;
	skb.tail = skb.transport_header + sizeof(struct tcphdr);
	return skb;
}

static void check_key(struct sk_buff *skb, bool ipv6)
{
	struct tuples_key key = {};

	require(tcp_offload_skb_key(skb, &key), "valid TCP skb rejected");
	require(key.l4proto == IPPROTO_TCP, "incorrect protocol");
	require(key.sport == bpf_htons(12345) && key.dport == bpf_htons(443),
		"TCP ports read from wrong header");
	if (ipv6) {
		require(!memcmp(key.sip.u6_addr8, packet + 40, 16) &&
			!memcmp(key.dip.u6_addr8, packet + 56, 16),
			"incorrect IPv6 addresses");
	} else {
		require(key.sip.u6_addr32[2] == bpf_htonl(0xffff) &&
			key.dip.u6_addr32[2] == bpf_htonl(0xffff) &&
			!memcmp(key.sip.u6_addr8 + 12, packet + 44, 4) &&
			!memcmp(key.dip.u6_addr8 + 12, packet + 48, 4),
			"incorrect IPv4-mapped addresses");
	}
}

static void check_headers(void)
{
	struct tuples_key key = {};
	struct sk_buff skb = fixture(false, IPPROTO_TCP, 0);

	check_key(&skb, false);
	skb = fixture(false, IPPROTO_TCP, 12);
	check_key(&skb, false);
	skb = fixture(true, IPPROTO_TCP, 0);
	check_key(&skb, true);
	skb = fixture(true, IPPROTO_DSTOPTS, 8);
	check_key(&skb, true);
	skb = fixture(true, IPPROTO_HOPOPTS, 16);
	packet[72] = IPPROTO_ROUTING;
	packet[73] = 0;
	packet[80] = IPPROTO_TCP;
	check_key(&skb, true);
	skb = fixture(true, IPPROTO_AH, 12);
	packet[73] = 1;
	check_key(&skb, true);
	skb = fixture(true, IPPROTO_FRAGMENT, 8);
	check_key(&skb, true);

	skb.transport_header = 0xffff;
	require(!tcp_offload_skb_key(&skb, &key), "unset transport offset accepted");
	skb.transport_header = skb.network_header + 20;
	require(!tcp_offload_skb_key(&skb, &key), "offset inside IPv6 header accepted");
	skb = fixture(true, IPPROTO_DSTOPTS, 8);
	skb.tail--;
	require(!tcp_offload_skb_key(&skb, &key), "truncated TCP header accepted");
	skb = fixture(true, IPPROTO_TCP, 0);
	fail_read = true;
	require(!tcp_offload_skb_key(&skb, &key), "failed kernel read accepted");
	fail_read = false;
	packet[32] = 0;
	require(!tcp_offload_skb_key(&skb, &key), "unknown IP version accepted");
}

int main(int argc, char **argv)
{
	require(argc == 2, "expected abi or headers argument");
	if (!strcmp(argv[1], "abi"))
		check_ports();
	else
		check_headers();
	return 0;
}
