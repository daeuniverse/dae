/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * Observation-only TC programs for direct (pass-through) traffic accounting.
 *
 * They are attached beside tproxy on the WAN/LAN interfaces dae already owns,
 * run first (lower priority), never modify packets or marks, and always return
 * TC_ACT_UNSPEC so the chain continues into tproxy. They only count flows that
 * tproxy has already recorded in conn_state_map as direct pass-through: a
 * stateful flow whose first packet was handled by dae. Packets without a state
 * entry are not counted.
 *
 * Upload is observed at LAN ingress (a forwarded client packet) and at WAN
 * egress, where the ingress_ifindex guard leaves only locally generated
 * sockets: forwarded packets were counted at LAN ingress and must not be
 * counted twice. Download is observed at WAN ingress, the only hook every reply
 * crosses. `direct_reverse_map` carries the NAT-independent flow index that
 * makes the reply side matchable on a masquerading gateway, where SNAT rewrites
 * the destination and the reversed tuple no longer reaches conn_state_map.
 *
 * conn_state_map is shared with tproxy.c and is reached through
 * CollectionOptions.MapReplacements, so the key and value layouts below must
 * mirror control/kern/tproxy.c exactly. The observer only reads that map.
 */

#include "headers/errno-base.h"
#include "headers/if_ether_defs.h"
#include "headers/pkt_cls_defs.h"
#include "headers/socket_defs.h"
#include "headers/upai_in6_defs.h"
#include "headers/vmlinux.h"

#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"

#include "ebpf_sync_defs.h"

#define DIRECT_STATS_CONTINUE TC_ACT_UNSPEC

#define IPV6_BYTE_LENGTH 16
#define TASK_COMM_LEN 16
#define MAX_CONN_STATE_NUM (65536 * 4)

// Keys of direct_stats_map. Userspace sums the copies across CPUs.
enum direct_stats_key {
	DIRECT_STATS_UPLOAD_BYTES = 0,
	DIRECT_STATS_UPLOAD_PACKETS = 1,
	DIRECT_STATS_DOWNLOAD_BYTES = 2,
	DIRECT_STATS_DOWNLOAD_PACKETS = 3,
	DIRECT_STATS_KEY_NUM = 4,
};

union ip6 {
	__u8 u6_addr8[16];
	__be16 u6_addr16[8];
	__be32 u6_addr32[4];
	__be64 u6_addr64[2];
};

struct tuples_key {
	union ip6 sip;
	union ip6 dip;
	__u16 sport;
	__u16 dport;
	__u8 l4proto;
};

union routing_meta {
	struct {
		__u32 mark;
		__u8 outbound;
		__u8 must;
		__u8 dscp;
		__u8 has_routing;
	} data;
	__u64 raw;
} __attribute__((aligned(8)));

// Mirrors struct conn_state in control/kern/tproxy.c. Keep field order and
// types identical: the map value is shared between the two objects.
struct conn_state {
	bool is_wan_ingress_direction;
	__u8 state;
	__u64 last_seen_ns;
	union routing_meta meta;
	__u8 mac[6];
	__u8 padding[2];
	__u8 pname[TASK_COMM_LEN];
	__u32 pid;
	__u8 routing_epoch_slot;
	__u8 direct_passthrough;
	__u16 datapath_generation;
};

// Read-only from this object. Replaced by the tproxy map at load time.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CONN_STATE_NUM);
	__type(key, struct tuples_key);
	__type(value, struct conn_state);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} conn_state_map SEC(".maps");

// Per-packet increments must not share one cacheline across CPUs.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, DIRECT_STATS_KEY_NUM);
	__type(key, __u32);
	__type(value, __u64);
} direct_stats_map SEC(".maps");

// NAT-independent index of direct flows, read in the reply direction.
//
// On a masquerading gateway SNAT rewrites the destination of a reply to the WAN
// address, so reversing its tuple never matches the conn_state entry the
// upload created. What survives translation is the remote endpoint and the
// local port (SNAT preserves the port unless it has to remap a collision), so
// those fields are the key. The value is refreshed on both directions and
// doubles as an LRU access. Only flows the datapath forwarded directly are
// recorded, so a proxied flow can never be recognised here.
struct direct_reverse_key {
	union ip6 remote_ip;
	__u16 remote_port;
	__u16 local_port;
	__u8 l4proto;
	__u8 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072);
	__type(key, struct direct_reverse_key);
	__type(value, __u64);
} direct_reverse_map SEC(".maps");

// Builds the tuple of the packet at l3_off in the same representation as
// tproxy's get_tuples. Non-first IP fragments and L4 protocols other than
// TCP/UDP are rejected, as they have no state entry to match.
static __always_inline int
direct_stats_parse_tuple(struct __sk_buff *skb, __u32 l3_off,
			 struct tuples_key *key)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u8 *p = data + l3_off;
	__u8 l4proto;
	__u32 l4_off;

	if ((void *)(p + 1) > data_end)
		return -1;

	__builtin_memset(key, 0, sizeof(*key));

	if ((p[0] >> 4) == 4) {
		struct iphdr *iph = (void *)p;

		if ((void *)(iph + 1) > data_end)
			return -1;
		if (iph->ihl < 5)
			return -1;
		// Only the first fragment carries the L4 header.
		if (iph->frag_off & bpf_htons(0x1fff))
			return -1;
		l4proto = iph->protocol;
		l4_off = l3_off + iph->ihl * 4;

		key->sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		key->sip.u6_addr32[3] = iph->saddr;
		key->dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		key->dip.u6_addr32[3] = iph->daddr;
	} else if ((p[0] >> 4) == 6) {
		struct ipv6hdr *ip6h = (void *)p;

		if ((void *)(ip6h + 1) > data_end)
			return -1;
		// Extension headers are not walked: such flows are skipped.
		l4proto = ip6h->nexthdr;
		l4_off = l3_off + sizeof(struct ipv6hdr);

		__builtin_memcpy(&key->sip, &ip6h->saddr, IPV6_BYTE_LENGTH);
		__builtin_memcpy(&key->dip, &ip6h->daddr, IPV6_BYTE_LENGTH);
	} else {
		return -1;
	}

	if (l4proto == IPPROTO_TCP) {
		struct tcphdr *tcph = data + l4_off;

		if ((void *)(tcph + 1) > data_end)
			return -1;
		key->sport = tcph->source;
		key->dport = tcph->dest;
	} else if (l4proto == IPPROTO_UDP) {
		struct udphdr *udph = data + l4_off;

		if ((void *)(udph + 1) > data_end)
			return -1;
		key->sport = udph->source;
		key->dport = udph->dest;
	} else {
		return -1;
	}
	key->l4proto = l4proto;
	return 0;
}

// Reports whether a conn_state entry belongs to a flow the datapath forwards
// without userspace. The flag is set by the hook that made the decision, so
// this is a fact about the flow rather than an inference from its routing
// shape. The routing half is a staleness guard: a tuple can be republished
// with a proxy decision without the entry being re-created.
static __always_inline bool
direct_stats_is_direct(const struct conn_state *st)
{
	if (!st || !st->direct_passthrough)
		return false;
	return !st->meta.data.has_routing ||
	       st->meta.data.outbound == OUTBOUND_DIRECT;
}

static __always_inline void
direct_stats_reverse(const struct tuples_key *in, struct tuples_key *out)
{
	out->sip = in->dip;
	out->dip = in->sip;
	out->sport = in->dport;
	out->dport = in->sport;
	out->l4proto = in->l4proto;
}

// Records the upload tuple of a direct flow under the NAT-independent key.
static __always_inline void
direct_stats_remember(const struct tuples_key *key)
{
	struct direct_reverse_key rk = {};
	__u64 now = bpf_ktime_get_ns();

	rk.remote_ip = key->dip;
	rk.remote_port = key->dport;
	rk.local_port = key->sport;
	rk.l4proto = key->l4proto;
	bpf_map_update_elem(&direct_reverse_map, &rk, &now, BPF_ANY);
}

// A reply must arrive while the index entry is still fresh. A finished flow
// leaves its key behind (the map is an LRU, not a timer), so without an age
// bound a later flow that reuses the port could be counted as direct.
#define DIRECT_STATS_REVERSE_MAX_AGE_NS (300ULL * 1000000000ULL)

// Answers whether a reply packet belongs to a recorded direct flow. The caller
// passes the packet's own tuple, so its source is the remote endpoint. A hit
// refreshes the entry.
static __always_inline bool
direct_stats_known(const struct tuples_key *key)
{
	struct direct_reverse_key rk = {};
	__u64 *last_seen;

	rk.remote_ip = key->sip;
	rk.remote_port = key->sport;
	rk.local_port = key->dport;
	rk.l4proto = key->l4proto;

	last_seen = bpf_map_lookup_elem(&direct_reverse_map, &rk);
	if (!last_seen)
		return false;
	__u64 now = bpf_ktime_get_ns();
	if (now > *last_seen && now - *last_seen > DIRECT_STATS_REVERSE_MAX_AGE_NS) {
		bpf_map_delete_elem(&direct_reverse_map, &rk);
		return false;
	}
	*last_seen = now;
	return true;
}

static __always_inline void
direct_stats_add(__u32 bytes_key, __u32 packets_key, __u64 len)
{
	__u64 *v;

	v = bpf_map_lookup_elem(&direct_stats_map, &bytes_key);
	if (v)
		*v += len;
	v = bpf_map_lookup_elem(&direct_stats_map, &packets_key);
	if (v)
		*v += 1;
}

enum direct_stats_role {
	DIRECT_STATS_ROLE_BOTH = 0,
	DIRECT_STATS_ROLE_LAN = 1,
	DIRECT_STATS_ROLE_WAN = 2,
};

// Ingress observer. Userspace picks the variant from the interface role, so a
// LAN-only hook never pays for the reply-side lookups and a WAN-only hook never
// pays for the upload-side one. An interface that carries both roles (a single
// arm) gets the BOTH variant, which resolves the direction per packet: the
// reply's tuple is the reverse of the state key, the upload's tuple is the
// state key as-is. `role` is a compile-time constant at every call site, so
// the unused branches are removed from each program.
static __always_inline int
direct_stats_ingress(struct __sk_buff *skb, __u32 l3_off, __u32 role)
{
	struct tuples_key key, rkey;
	struct conn_state *st;
	__u64 len = skb->len;

	if (direct_stats_parse_tuple(skb, l3_off, &key))
		return DIRECT_STATS_CONTINUE;

	// tuples_key has tail padding, and conn_state_map hashes the whole key, so
	// the reversed key must be fully initialized before it is looked up.
	__builtin_memset(&rkey, 0, sizeof(rkey));

	// A live entry settles the flow: only direct flows are counted and the
	// NAT index holds direct flows exclusively, so a proxied packet stops at
	// the entry after a single lookup.
	if (role != DIRECT_STATS_ROLE_LAN) {
		// Download: the packet is the reply, so its reversed tuple is the key.
		direct_stats_reverse(&key, &rkey);
		st = bpf_map_lookup_elem(&conn_state_map, &rkey);
		if (st) {
			if (direct_stats_is_direct(st)) {
				direct_stats_add(DIRECT_STATS_DOWNLOAD_BYTES,
						 DIRECT_STATS_DOWNLOAD_PACKETS, len);
				direct_stats_remember(&rkey);
			}
			return DIRECT_STATS_CONTINUE;
		}
	}

	if (role != DIRECT_STATS_ROLE_WAN) {
		// Upload: the packet is the original direction.
		st = bpf_map_lookup_elem(&conn_state_map, &key);
		if (st) {
			if (direct_stats_is_direct(st)) {
				direct_stats_add(DIRECT_STATS_UPLOAD_BYTES,
						 DIRECT_STATS_UPLOAD_PACKETS, len);
				direct_stats_remember(&key);
			}
			return DIRECT_STATS_CONTINUE;
		}
	}

	// NAT gateway: SNAT rewrote the reply's destination, so the reversed tuple
	// cannot reach the entry the upload created. The three-field index survives
	// the translation because SNAT preserves the local port.
	if (role != DIRECT_STATS_ROLE_LAN && direct_stats_known(&key))
		direct_stats_add(DIRECT_STATS_DOWNLOAD_BYTES,
				 DIRECT_STATS_DOWNLOAD_PACKETS, len);

	return DIRECT_STATS_CONTINUE;
}

// WAN-egress observer. Only locally generated packets reach it: anything with
// an ingress interface was forwarded and its upload was already counted at the
// LAN ingress hook.
static __always_inline int
direct_stats_egress(struct __sk_buff *skb, __u32 l3_off)
{
	struct tuples_key key;
	struct conn_state *st;
	__u64 len = skb->len;

	if (skb->ingress_ifindex != 0)
		return DIRECT_STATS_CONTINUE;
	if (direct_stats_parse_tuple(skb, l3_off, &key))
		return DIRECT_STATS_CONTINUE;

	st = bpf_map_lookup_elem(&conn_state_map, &key);
	if (direct_stats_is_direct(st)) {
		direct_stats_add(DIRECT_STATS_UPLOAD_BYTES,
				 DIRECT_STATS_UPLOAD_PACKETS, len);
		direct_stats_remember(&key);
	}
	return DIRECT_STATS_CONTINUE;
}

SEC("tc/direct_stats_ingress_l2")
int direct_stats_ingress_l2(struct __sk_buff *skb)
{
	return direct_stats_ingress(skb, 14, DIRECT_STATS_ROLE_BOTH);
}

SEC("tc/direct_stats_ingress_l3")
int direct_stats_ingress_l3(struct __sk_buff *skb)
{
	return direct_stats_ingress(skb, 0, DIRECT_STATS_ROLE_BOTH);
}

SEC("tc/direct_stats_lan_ingress_l2")
int direct_stats_lan_ingress_l2(struct __sk_buff *skb)
{
	return direct_stats_ingress(skb, 14, DIRECT_STATS_ROLE_LAN);
}

SEC("tc/direct_stats_lan_ingress_l3")
int direct_stats_lan_ingress_l3(struct __sk_buff *skb)
{
	return direct_stats_ingress(skb, 0, DIRECT_STATS_ROLE_LAN);
}

SEC("tc/direct_stats_wan_ingress_l2")
int direct_stats_wan_ingress_l2(struct __sk_buff *skb)
{
	return direct_stats_ingress(skb, 14, DIRECT_STATS_ROLE_WAN);
}

SEC("tc/direct_stats_wan_ingress_l3")
int direct_stats_wan_ingress_l3(struct __sk_buff *skb)
{
	return direct_stats_ingress(skb, 0, DIRECT_STATS_ROLE_WAN);
}

SEC("tc/direct_stats_egress_l2")
int direct_stats_egress_l2(struct __sk_buff *skb)
{
	return direct_stats_egress(skb, 14);
}

SEC("tc/direct_stats_egress_l3")
int direct_stats_egress_l3(struct __sk_buff *skb)
{
	return direct_stats_egress(skb, 0);
}

SEC("license") const char __license[] = "Dual BSD/GPL";
