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
 * counted twice.
 *
 * Download is observed at two places:
 *   - WAN ingress, but only for packets delivered to a local socket. A reply
 *     that is forwarded to a LAN client is counted on the LAN egress hook
 *     instead, after DNAT. That is what makes a masquerading gateway countable:
 *     the reply reaches the LAN egress hook with the client's address, so the
 *     reversed tuple matches conn_state_map even though the WAN-ingress packet
 *     carried the pre-DNAT destination.
 *   - LAN egress, for forwarded replies only (ingress_ifindex != 0). The
 *     reverse tuple of the post-DNAT packet is the LAN upload key.
 *
 * A dual-role interface runs the combined WAN-ingress program, which keeps the
 * single-hook WAN-ingress download accounting; a separate LAN egress hook is
 * not attached for it, so that case cannot distinguish the two directions on
 * egress and retains the pre-DNAT limitation.
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

// Enough for a normal IPv6 chain and a couple of encapsulations. The bound also
// keeps the variable l4_off bounded for the verifier.
#define DIRECT_STATS_MAX_IPV6_EXT 8
#define DIRECT_STATS_MAX_HEADER_LEN 2048
#define DIRECT_STATS_HEADER_PULL 128
#define DIRECT_STATS_MAX_VLAN_TAGS 4

// Socket mark dae puts on its own sockets. Userspace writes the value from
// so_mark_from_dae before loading the object. Zero means "no mark known", which
// disables the local-socket exclusion rather than excluding every socket.
const volatile __u32 DIRECT_STATS_DAE_SOCKET_MARK = 0;

// Keys of direct_stats_map. Userspace sums the copies across CPUs. Each key
// carries both bytes and packets so a direct packet performs one map lookup
// instead of one lookup per counter.
enum direct_stats_key {
	DIRECT_STATS_UPLOAD = 0,
	DIRECT_STATS_DOWNLOAD = 1,
	DIRECT_STATS_KEY_NUM = 2,
};

struct direct_stats_value {
	__u64 bytes;
	__u64 packets;
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
	__type(value, struct direct_stats_value);
} direct_stats_map SEC(".maps");

static __always_inline bool
direct_stats_is_ipv6_extension(__u8 nexthdr)
{
	switch (nexthdr) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
	case IPPROTO_DSTOPTS:
	case IPPROTO_AH:
	case IPPROTO_MH:
		return true;
	default:
		return false;
	}
}

static __always_inline __u32
direct_stats_ipv6_extension_len(__u8 nexthdr, __u8 len_field)
{
	/* AH encodes its length in 4-octet units excluding the first 8 octets. */
	if (nexthdr == IPPROTO_AH)
		return ((__u32)len_field + 2) * 4;
	return ((__u32)len_field + 1) * 8;
}

// Builds the tuple of the packet at l3_off in the same representation as
// tproxy's get_tuples. IPv6 extension headers are walked; non-first fragments
// and L4 protocols other than TCP/UDP are rejected, as they have no state entry
// to match. The pull makes non-linear headers readable, matching tproxy's
// parser; it does not change packet contents or the forwarding decision.
static __always_inline int
direct_stats_parse_tuple(struct __sk_buff *skb, __u32 l3_off,
			 struct tuples_key *key)
{
	void *data;
	void *data_end;
	__u8 *p;
	__u8 l4proto;
	__u32 l4_off;

	// Short frames (a 42-byte UDP packet, a 54-byte TCP ACK) used to fail
	// the pull because the helper refuses a length longer than the skb. Pull
	// only what the packet actually has; the header checks below decide
	// whether enough bytes are present for the tuple.
	__u32 pull = skb->len < DIRECT_STATS_HEADER_PULL ?
		skb->len : DIRECT_STATS_HEADER_PULL;
	if (bpf_skb_pull_data(skb, pull))
		return -1;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	// The kernel strips an 802.1Q/802.1ad tag before TC ingress, but TC egress
	// can still see a tag that vlan_dev_hard_start_xmit has not pushed yet, and
	// a second (QinQ) tag can survive on ingress. Walk the tags that are still
	// in the packet so both paths use the same l3 offset. l3_off == 0 means the
	// hook is on an L3 device and there is no Ethernet header to inspect.
	if (l3_off == 14) {
		struct ethhdr *eth = data;
		__be16 proto;

		if ((void *)(eth + 1) > data_end)
			return -1;
		proto = eth->h_proto;
#pragma unroll
		for (int i = 0; i < DIRECT_STATS_MAX_VLAN_TAGS; i++) {
			struct vlan_hdr *vhdr;

			if (proto != bpf_htons(ETH_P_8021Q) &&
			    proto != bpf_htons(ETH_P_8021AD))
				break;
			vhdr = data + l3_off;
			if ((void *)(vhdr + 1) > data_end)
				return -1;
			proto = vhdr->h_vlan_encapsulated_proto;
			l3_off += 4;
		}
	}
	p = data + l3_off;

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
		__u32 off;
		__u8 nexthdr;

		if ((void *)(ip6h + 1) > data_end)
			return -1;
		// tproxy's get_tuples stores the IPv6 addresses in the same
		// representation. Leaving them zero made every IPv6 lookup miss.
		__builtin_memcpy(&key->sip, &ip6h->saddr, IPV6_BYTE_LENGTH);
		__builtin_memcpy(&key->dip, &ip6h->daddr, IPV6_BYTE_LENGTH);
		nexthdr = ip6h->nexthdr;
		off = l3_off + sizeof(struct ipv6hdr);

#pragma unroll
		for (int i = 0; i < DIRECT_STATS_MAX_IPV6_EXT; i++) {
			if (nexthdr == IPPROTO_NONE)
				return -1;
			if (!direct_stats_is_ipv6_extension(nexthdr))
				break;
			if (nexthdr == IPPROTO_FRAGMENT) {
				struct frag_hdr *fragh = data + off;

				if ((void *)(fragh + 1) > data_end)
					return -1;
				if (fragh->frag_off & bpf_htons(0xfff8))
					return -1;
				nexthdr = fragh->nexthdr;
				off += sizeof(struct frag_hdr);
				continue;
			}

			__u8 *ext = data + off;

			if ((void *)(ext + 2) > data_end)
				return -1;
			__u8 cur_hdr = nexthdr;
			__u8 ext_len = ext[1];

			nexthdr = ext[0];
			off += direct_stats_ipv6_extension_len(cur_hdr, ext_len);
			if (off > DIRECT_STATS_MAX_HEADER_LEN)
				return -1;
		}
		if (direct_stats_is_ipv6_extension(nexthdr))
			return -1;
		l4proto = nexthdr;
		l4_off = off;
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

static __always_inline void
direct_stats_add(__u32 key, __u64 len)
{
	struct direct_stats_value *v;

	v = bpf_map_lookup_elem(&direct_stats_map, &key);
	if (!v)
		return;
	v->bytes += len;
	v->packets += 1;
}

// IPv4 keys use the ::ffff:0:0/96 sentinel in the first two words, exactly like
// tproxy's get_tuples.
static __always_inline bool
direct_stats_is_ipv4(const struct tuples_key *key)
{
	return key->sip.u6_addr32[2] == bpf_htonl(0x0000ffff) &&
	       key->dip.u6_addr32[2] == bpf_htonl(0x0000ffff);
}

static __always_inline bool
direct_stats_sock_is_dae(struct bpf_sock *sk)
{
	struct bpf_sock *fullsock;

	if (!sk || !DIRECT_STATS_DAE_SOCKET_MARK)
		return false;
	fullsock = bpf_sk_fullsock(sk);
	return fullsock && fullsock->mark == DIRECT_STATS_DAE_SOCKET_MARK;
}

// Whether the matched socket is bound to the packet's exact destination
// address. A wildcard-bound socket answers for every destination and therefore
// says nothing about local delivery; only an exact match proves this is a
// host-terminated flow rather than a forwarded one.
static __always_inline bool
direct_stats_sock_bound_to_daddr(struct bpf_sock *sk,
				 const struct tuples_key *key, bool ipv4)
{
	if (ipv4) {
		__u32 bound = sk->src_ip4;

		return bound != 0 && bound == key->dip.u6_addr32[3];
	}

	// Read the four words with constant offsets. Materializing a pointer
	// (`const __u32 *bound = sk->src_ip6`) makes clang add a register to
	// PTR_TO_SOCK, which the verifier rejects as pointer arithmetic on sock.
	__u32 b0 = sk->src_ip6[0];
	__u32 b1 = sk->src_ip6[1];
	__u32 b2 = sk->src_ip6[2];
	__u32 b3 = sk->src_ip6[3];
	bool wildcard = !(b0 | b1 | b2 | b3);

	return !wildcard &&
	       b0 == key->dip.u6_addr32[0] &&
	       b1 == key->dip.u6_addr32[1] &&
	       b2 == key->dip.u6_addr32[2] &&
	       b3 == key->dip.u6_addr32[3];
}

// Distinguishes a reply delivered to a local socket from one forwarded to a LAN
// client. Forwarded replies are accounted on the LAN egress hook after DNAT;
// counting them here as well would double count non-NAT clients.
static __always_inline bool
direct_stats_has_local_socket(struct __sk_buff *skb,
			      const struct tuples_key *key)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;
	__u32 tuple_size;
	bool ipv4 = direct_stats_is_ipv4(key);
	bool local;

	if (ipv4) {
		tuple.ipv4.saddr = key->sip.u6_addr32[3];
		tuple.ipv4.daddr = key->dip.u6_addr32[3];
		tuple.ipv4.sport = key->sport;
		tuple.ipv4.dport = key->dport;
		tuple_size = sizeof(tuple.ipv4);
	} else {
		__builtin_memcpy(tuple.ipv6.saddr, &key->sip, IPV6_BYTE_LENGTH);
		__builtin_memcpy(tuple.ipv6.daddr, &key->dip, IPV6_BYTE_LENGTH);
		tuple.ipv6.sport = key->sport;
		tuple.ipv6.dport = key->dport;
		tuple_size = sizeof(tuple.ipv6);
	}

	if (key->l4proto == IPPROTO_TCP)
		sk = bpf_sk_lookup_tcp(skb, &tuple, tuple_size,
				       (__u64)(s32)-1, 0);
	else if (key->l4proto == IPPROTO_UDP)
		sk = bpf_sk_lookup_udp(skb, &tuple, tuple_size,
				       (__u64)(s32)-1, 0);
	else
		return false;

	if (!sk)
		return false;
	local = !direct_stats_sock_is_dae(sk) &&
		direct_stats_sock_bound_to_daddr(sk, key, ipv4);
	bpf_sk_release(sk);
	return local;
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

	// A live entry settles the flow: only direct flows are counted, so a
	// proxied packet stops at the entry after a single lookup.
	if (role != DIRECT_STATS_ROLE_LAN) {
		// Download: the packet is the reply, so its reversed tuple is the key.
		direct_stats_reverse(&key, &rkey);
		st = bpf_map_lookup_elem(&conn_state_map, &rkey);
		if (st) {
			if (direct_stats_is_direct(st)) {
				// A dual-role interface has no separate LAN egress
				// hook: keep the single-hook accounting there.
				if (role == DIRECT_STATS_ROLE_BOTH ||
				    direct_stats_has_local_socket(skb, &key))
					direct_stats_add(DIRECT_STATS_DOWNLOAD, len);
				return DIRECT_STATS_CONTINUE;
			}
			// An entry that carries a routing decision belongs to a proxied
			// flow.
			if (st->meta.data.has_routing)
				return DIRECT_STATS_CONTINUE;
		}
	}

	if (role != DIRECT_STATS_ROLE_WAN) {
		// Upload: the packet is the original direction.
		st = bpf_map_lookup_elem(&conn_state_map, &key);
		if (st) {
			if (direct_stats_is_direct(st))
				direct_stats_add(DIRECT_STATS_UPLOAD, len);
			return DIRECT_STATS_CONTINUE;
		}
	}

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
	if (direct_stats_is_direct(st))
		direct_stats_add(DIRECT_STATS_UPLOAD, len);
	return DIRECT_STATS_CONTINUE;
}

// LAN-egress observer for forwarded replies. NAT rewrites the WAN-ingress
// destination, but the reply leaving the LAN interface has already been
// DNATed, so its reverse tuple is the LAN upload key even on a masquerading
// gateway. Locally generated packets (ingress_ifindex == 0) are excluded:
// host-to-LAN traffic is not a WAN download.
static __always_inline int
direct_stats_lan_egress(struct __sk_buff *skb, __u32 l3_off)
{
	struct tuples_key key, rkey;
	struct conn_state *st;
	__u64 len = skb->len;

	if (skb->ingress_ifindex == 0)
		return DIRECT_STATS_CONTINUE;
	if (direct_stats_parse_tuple(skb, l3_off, &key))
		return DIRECT_STATS_CONTINUE;

	__builtin_memset(&rkey, 0, sizeof(rkey));
	direct_stats_reverse(&key, &rkey);
	st = bpf_map_lookup_elem(&conn_state_map, &rkey);
	if (direct_stats_is_direct(st))
		direct_stats_add(DIRECT_STATS_DOWNLOAD, len);
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

SEC("tc/direct_stats_lan_egress_l2")
int direct_stats_lan_egress_l2(struct __sk_buff *skb)
{
	return direct_stats_lan_egress(skb, 14);
}

SEC("tc/direct_stats_lan_egress_l3")
int direct_stats_lan_egress_l3(struct __sk_buff *skb)
{
	return direct_stats_lan_egress(skb, 0);
}

SEC("license") const char __license[] = "Dual BSD/GPL";
