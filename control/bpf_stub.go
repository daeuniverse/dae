//go:build dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"io"
	"structs"

	"github.com/cilium/ebpf"
)

var errBpfObjectsUnavailable = errors.New("eBPF objects are unavailable in this build; this is a stub build (tag dae_stub_ebpf); run make ebpf before building")

// bpfDaeParam corresponds to C struct dae_param in tproxy.c
// IMPORTANT: use_redirect_peer is DISABLED in C code due to kernel panic issues.
// The field is preserved here for ABI compatibility only—value is always 0.
type bpfDaeParam struct {
	_               structs.HostLayout
	TproxyPort      uint32
	ControlPlanePid uint32
	Dae0Ifindex     uint32
	DaeNetnsId      uint32
	Dae0peerMac     [6]uint8
	UseRedirectPeer uint8 // Always 0 - bpf_redirect_peer() disabled in C
	Padding         uint8
}

type bpfDomainRouting struct {
	_      structs.HostLayout
	Bitmap [32]uint32
}

type bpfMatchSet struct {
	_        structs.HostLayout
	Value    [16]uint8
	Not      bool
	Type     uint8
	Outbound uint8
	Must     bool
	Mark     uint32
}

type bpfOutboundConnectivityQuery struct {
	_         structs.HostLayout
	Outbound  uint8
	L4proto   uint8
	Ipversion uint8
}

type bpfPidPname struct {
	_     structs.HostLayout
	Pid   uint32
	Pname [16]int8
}

type bpfPortRange struct {
	_         structs.HostLayout
	PortStart uint16
	PortEnd   uint16
}

type bpfRedirectEntry struct {
	_       structs.HostLayout
	Ifindex uint32
	Smac    [6]uint8
	Dmac    [6]uint8
	FromWan uint8
}

type bpfRedirectTuple struct {
	Sip struct {
		_       structs.HostLayout
		U6Addr8 [16]uint8
	}
	Dip struct {
		_       structs.HostLayout
		U6Addr8 [16]uint8
	}
}

type bpfRoutingResult struct {
	_        structs.HostLayout
	Mark     uint32
	Must     uint8
	Mac      [6]uint8
	Outbound uint8
	Pname    [16]uint8
	Pid      uint32
	Dscp     uint8
}

type bpfTuplesKey struct {
	_   structs.HostLayout
	Sip struct {
		_       structs.HostLayout
		U6Addr8 [16]uint8
	}
	Dip struct {
		_       structs.HostLayout
		U6Addr8 [16]uint8
	}
	Sport   uint16
	Dport   uint16
	L4proto uint8
}

type bpfUdpConnState struct {
	_                     structs.HostLayout
	IsWanIngressDirection bool
	LastSeenNs            uint64
}

func loadBpf() (*ebpf.CollectionSpec, error) {
	return nil, errBpfObjectsUnavailable
}

func loadBpfObjects(_ interface{}, _ *ebpf.CollectionOptions) error {
	return errBpfObjectsUnavailable
}

type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
	bpfVariableSpecs
}

type bpfProgramSpecs struct {
	TproxyDae0Ingress     *ebpf.ProgramSpec `ebpf:"tproxy_dae0_ingress"`
	TproxyDae0peerIngress *ebpf.ProgramSpec `ebpf:"tproxy_dae0peer_ingress"`
	TproxyLanEgressL2     *ebpf.ProgramSpec `ebpf:"tproxy_lan_egress_l2"`
	TproxyLanEgressL3     *ebpf.ProgramSpec `ebpf:"tproxy_lan_egress_l3"`
	TproxyLanIngressL2    *ebpf.ProgramSpec `ebpf:"tproxy_lan_ingress_l2"`
	TproxyLanIngressL3    *ebpf.ProgramSpec `ebpf:"tproxy_lan_ingress_l3"`
	// SOCK_OPS + SK_MSG stubs preserved for ABI compatibility (DISABLED due to kernel panic)
	TproxySockops          *ebpf.ProgramSpec `ebpf:"tproxy_sockops"`
	TproxySkMsgRedir       *ebpf.ProgramSpec `ebpf:"tproxy_sk_msg_redir"`
	TproxyWanCgConnect4    *ebpf.ProgramSpec `ebpf:"tproxy_wan_cg_connect4"`
	TproxyWanCgConnect6    *ebpf.ProgramSpec `ebpf:"tproxy_wan_cg_connect6"`
	TproxyWanCgSendmsg4    *ebpf.ProgramSpec `ebpf:"tproxy_wan_cg_sendmsg4"`
	TproxyWanCgSendmsg6    *ebpf.ProgramSpec `ebpf:"tproxy_wan_cg_sendmsg6"`
	TproxyWanCgSockCreate  *ebpf.ProgramSpec `ebpf:"tproxy_wan_cg_sock_create"`
	TproxyWanCgSockRelease *ebpf.ProgramSpec `ebpf:"tproxy_wan_cg_sock_release"`
	TproxyWanEgressL2      *ebpf.ProgramSpec `ebpf:"tproxy_wan_egress_l2"`
	TproxyWanEgressL3      *ebpf.ProgramSpec `ebpf:"tproxy_wan_egress_l3"`
	TproxyWanIngressL2     *ebpf.ProgramSpec `ebpf:"tproxy_wan_ingress_l2"`
	TproxyWanIngressL3     *ebpf.ProgramSpec `ebpf:"tproxy_wan_ingress_l3"`
}

type bpfMapSpecs struct {
	BpfStatsMap             *ebpf.MapSpec `ebpf:"bpf_stats_map"`
	CookiePidMap            *ebpf.MapSpec `ebpf:"cookie_pid_map"`
	DomainRoutingMap        *ebpf.MapSpec `ebpf:"domain_routing_map"`
	FastSock                *ebpf.MapSpec `ebpf:"fast_sock"`
	ListenSocketMap         *ebpf.MapSpec `ebpf:"listen_socket_map"`
	LpmArrayMap             *ebpf.MapSpec `ebpf:"lpm_array_map"`
	OutboundConnectivityMap *ebpf.MapSpec `ebpf:"outbound_connectivity_map"`
	RedirectTrack           *ebpf.MapSpec `ebpf:"redirect_track"`
	RoutingMap              *ebpf.MapSpec `ebpf:"routing_map"`
	RoutingMetaMap          *ebpf.MapSpec `ebpf:"routing_meta_map"`
	RoutingTuplesMap        *ebpf.MapSpec `ebpf:"routing_tuples_map"`
	UdpConnStateMap         *ebpf.MapSpec `ebpf:"udp_conn_state_map"`
	UnusedLpmType           *ebpf.MapSpec `ebpf:"unused_lpm_type"`
}

type bpfVariableSpecs struct {
	PARAM *ebpf.VariableSpec `ebpf:"PARAM"`
}

type bpfObjects struct {
	bpfPrograms
	bpfMaps
	bpfVariables
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

type bpfMaps struct {
	BpfStatsMap             *ebpf.Map `ebpf:"bpf_stats_map"`
	CookiePidMap            *ebpf.Map `ebpf:"cookie_pid_map"`
	DomainRoutingMap        *ebpf.Map `ebpf:"domain_routing_map"`
	FastSock                *ebpf.Map `ebpf:"fast_sock"`
	ListenSocketMap         *ebpf.Map `ebpf:"listen_socket_map"`
	LpmArrayMap             *ebpf.Map `ebpf:"lpm_array_map"`
	OutboundConnectivityMap *ebpf.Map `ebpf:"outbound_connectivity_map"`
	RedirectTrack           *ebpf.Map `ebpf:"redirect_track"`
	RoutingMap              *ebpf.Map `ebpf:"routing_map"`
	RoutingMetaMap          *ebpf.Map `ebpf:"routing_meta_map"`
	RoutingTuplesMap        *ebpf.Map `ebpf:"routing_tuples_map"`
	UdpConnStateMap         *ebpf.Map `ebpf:"udp_conn_state_map"`
	UnusedLpmType           *ebpf.Map `ebpf:"unused_lpm_type"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.BpfStatsMap,
		m.CookiePidMap,
		m.DomainRoutingMap,
		m.FastSock,
		m.ListenSocketMap,
		m.LpmArrayMap,
		m.OutboundConnectivityMap,
		m.RedirectTrack,
		m.RoutingMap,
		m.RoutingMetaMap,
		m.RoutingTuplesMap,
		m.UdpConnStateMap,
		m.UnusedLpmType,
	)
}

type bpfVariables struct {
	PARAM *ebpf.Variable `ebpf:"PARAM"`
}

type bpfPrograms struct {
	TproxyDae0Ingress     *ebpf.Program `ebpf:"tproxy_dae0_ingress"`
	TproxyDae0peerIngress *ebpf.Program `ebpf:"tproxy_dae0peer_ingress"`
	TproxyLanEgressL2     *ebpf.Program `ebpf:"tproxy_lan_egress_l2"`
	TproxyLanEgressL3     *ebpf.Program `ebpf:"tproxy_lan_egress_l3"`
	TproxyLanIngressL2    *ebpf.Program `ebpf:"tproxy_lan_ingress_l2"`
	TproxyLanIngressL3    *ebpf.Program `ebpf:"tproxy_lan_ingress_l3"`
	// SOCK_OPS + SK_MSG stubs preserved for ABI compatibility (DISABLED due to kernel panic)
	TproxySockops          *ebpf.Program `ebpf:"tproxy_sockops"`
	TproxySkMsgRedir       *ebpf.Program `ebpf:"tproxy_sk_msg_redir"`
	TproxyWanCgConnect4    *ebpf.Program `ebpf:"tproxy_wan_cg_connect4"`
	TproxyWanCgConnect6    *ebpf.Program `ebpf:"tproxy_wan_cg_connect6"`
	TproxyWanCgSendmsg4    *ebpf.Program `ebpf:"tproxy_wan_cg_sendmsg4"`
	TproxyWanCgSendmsg6    *ebpf.Program `ebpf:"tproxy_wan_cg_sendmsg6"`
	TproxyWanCgSockCreate  *ebpf.Program `ebpf:"tproxy_wan_cg_sock_create"`
	TproxyWanCgSockRelease *ebpf.Program `ebpf:"tproxy_wan_cg_sock_release"`
	TproxyWanEgressL2      *ebpf.Program `ebpf:"tproxy_wan_egress_l2"`
	TproxyWanEgressL3      *ebpf.Program `ebpf:"tproxy_wan_egress_l3"`
	TproxyWanIngressL2     *ebpf.Program `ebpf:"tproxy_wan_ingress_l2"`
	TproxyWanIngressL3     *ebpf.Program `ebpf:"tproxy_wan_ingress_l3"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.TproxyDae0Ingress,
		p.TproxyDae0peerIngress,
		p.TproxyLanEgressL2,
		p.TproxyLanEgressL3,
		p.TproxyLanIngressL2,
		p.TproxyLanIngressL3,
		p.TproxySockops,
		p.TproxySkMsgRedir,
		p.TproxyWanCgConnect4,
		p.TproxyWanCgConnect6,
		p.TproxyWanCgSendmsg4,
		p.TproxyWanCgSendmsg6,
		p.TproxyWanCgSockCreate,
		p.TproxyWanCgSockRelease,
		p.TproxyWanEgressL2,
		p.TproxyWanEgressL3,
		p.TproxyWanIngressL2,
		p.TproxyWanIngressL3,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if closer == nil {
			continue
		}
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}
