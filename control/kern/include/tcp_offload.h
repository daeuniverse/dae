/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org> */

#ifndef __DAE_TCP_OFFLOAD_H
#define __DAE_TCP_OFFLOAD_H

static __always_inline __be16 tcp_offload_remote_port(__u32 port)
{
	/* convert_skb_access shifts skc_dport only on little-endian kernels. */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return port >> 16;
#else
	return (__be16)port;
#endif
}

static __always_inline bool
tcp_offload_skb_key(struct sk_buff *skb, struct tuples_key *key)
{
	struct tcphdr tcp;
	unsigned char *head;
	__u32 tail;
	__u16 nh, th;
	__u8 version;

	if (BPF_CORE_READ_INTO(&nh, skb, network_header) ||
	    BPF_CORE_READ_INTO(&th, skb, transport_header) ||
	    BPF_CORE_READ_INTO(&tail, skb, tail) ||
	    BPF_CORE_READ_INTO(&head, skb, head))
		return false;

	/* IPv6 input has already walked extensions and set transport_header.
	 * tcp_read_skb -> sk_psock_verdict_recv -> sk_psock_skb_redirect ->
	 * sk_psock_backlog preserves these head-relative offsets (Linux 6.12,
	 * net/ipv6/{ip6_input,exthdrs}.c and net/core/skmsg.c). skb->data may
	 * point at payload here, so neither it nor a fixed IPv6 +40 is TCP.
	 */
	if (!head || th == (__u16)~0U || th < nh ||
	    (__u32)th + sizeof(tcp) > tail)
		return false;
	if (bpf_probe_read_kernel(&version, sizeof(version), head + nh))
		return false;

	/* version is the raw first IP byte, so the version nibble is tested by
	 * mask rather than by shift: a shift right by four here is
	 * indistinguishable from a UAPI bitfield extraction in the object code,
	 	 * and the datapath keeps the big-endian object free of those .
	 * The two forms are equivalent for a byte: >> 4 == 4 iff the high
	 * nibble is 4.
	 */
	if ((version & 0xf0) == 0x40) {
		struct iphdr ip4;
		__u16 ihl = (version & 0xf) * 4;

		if (ihl < sizeof(ip4) || th - nh != ihl)
			return false;
		if (bpf_probe_read_kernel(&ip4, sizeof(ip4), head + nh))
			return false;
		if (ip4.protocol != IPPROTO_TCP)
			return false;
		key->sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		key->sip.u6_addr32[3] = ip4.saddr;
		key->dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		key->dip.u6_addr32[3] = ip4.daddr;
	} else if ((version & 0xf0) == 0x60) {
		struct ipv6hdr ip6;

		if (th - nh < sizeof(ip6))
			return false;
		if (bpf_probe_read_kernel(&ip6, sizeof(ip6), head + nh))
			return false;
		__builtin_memcpy(&key->sip, &ip6.saddr, IPV6_BYTE_LENGTH);
		__builtin_memcpy(&key->dip, &ip6.daddr, IPV6_BYTE_LENGTH);
	} else {
		return false;
	}
	if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + th))
		return false;
	key->l4proto = IPPROTO_TCP;
	key->sport = tcp.source;
	key->dport = tcp.dest;
	return true;
}

#endif /* __DAE_TCP_OFFLOAD_H */
