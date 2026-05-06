//go:build dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"structs"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
)

var errBpfObjectsUnavailable = errors.New("eBPF objects are unavailable in this build; this is a stub build (tag dae_stub_ebpf); run make ebpf before building")

// bpfDaeParam corresponds to C struct dae_param in tproxy.c
// use_redirect_peer enables bpf_redirect_peer() optimization for TC ingress.
// Only safe with: (1) netkit device + scrub=NONE, (2) kernel >= 6.8 (CVE-2025-37959 fix).
// When enabled, provides ~50% throughput improvement by bypassing CPU backlog.
type bpfDaeParam struct {
	_                    structs.HostLayout
	TproxyPort           uint32
	ControlPlanePid      uint32
	Dae0Ifindex          uint32
	DaeNetnsId           uint32
	Dae0peerMac          [6]uint8
	PaddingAfterMac      [2]uint8
	UseRedirectPeer      uint8 // 0=use bpf_redirect(), 1=use bpf_redirect_peer() when safe
	HasBpfGetCurrentTask uint8
	Padding2             uint16
	DaeSocketMark        uint32 // mark set on dae's own sockets to identify them in eBPF
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

type bpfPidPname struct {
	_          structs.HostLayout
	LastSeenNs uint64
	Pid        uint32
	Pname      [16]int8
}

type bpfPortRange struct {
	_         structs.HostLayout
	PortStart uint16
	PortEnd   uint16
}

type bpfRedirectEntry struct {
	_          structs.HostLayout
	Ifindex    uint32
	Smac       [6]uint8
	Dmac       [6]uint8
	FromWan    uint8
	Padding    [3]uint8
	LastSeenNs uint64
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

type bpfRoutingHandoffEntry struct {
	_          structs.HostLayout
	LastSeenNs uint64
	Result     bpfRoutingResult
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
	_       [3]uint8
}

type bpfUdpConnState struct {
	_                     structs.HostLayout
	IsWanIngressDirection bool
	_                     [7]byte
	LastSeenNs            uint64
	Meta                  struct {
		_    structs.HostLayout
		Data struct {
			_          structs.HostLayout
			Mark       uint32
			Outbound   uint8
			Must       uint8
			Dscp       uint8
			HasRouting uint8
		}
	}
	Mac   [6]uint8
	_     [2]byte
	Pname [16]uint8
	Pid   uint32
}

type bpfTcpConnState struct {
	_                     structs.HostLayout
	IsWanIngressDirection bool
	State                 uint8
	_                     [6]byte
	LastSeenNs            uint64
	Meta                  struct {
		_    structs.HostLayout
		Data struct {
			_          structs.HostLayout
			Mark       uint32
			Outbound   uint8
			Must       uint8
			Dscp       uint8
			HasRouting uint8
		}
	}
	Mac   [6]uint8
	_     [2]byte
	Pname [16]uint8
	Pid   uint32
}

type bpfDaeEvent struct {
	_         structs.HostLayout
	Timestamp uint64
	Type      uint32
	Pid       uint32
	Pname     [16]uint8
	Outbound  uint8
	L4proto   uint8
	Pad       [2]uint8
	Sip       [4]uint32
	Dip       [4]uint32
	Sport     uint16
	Dport     uint16
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
	EventRingbuf            *ebpf.MapSpec `ebpf:"event_ringbuf"`
	FastSock                *ebpf.MapSpec `ebpf:"fast_sock"`
	ListenSocketMap         *ebpf.MapSpec `ebpf:"listen_socket_map"`
	LpmArrayMap             *ebpf.MapSpec `ebpf:"lpm_array_map"`
	OutboundConnectivityMap *ebpf.MapSpec `ebpf:"outbound_connectivity_map"`
	RedirectTrack           *ebpf.MapSpec `ebpf:"redirect_track"`
	RoutingHandoffMap       *ebpf.MapSpec `ebpf:"routing_handoff_map"`
	RoutingMap              *ebpf.MapSpec `ebpf:"routing_map"`
	RoutingMetaMap          *ebpf.MapSpec `ebpf:"routing_meta_map"`
	TcpConnStateMap         *ebpf.MapSpec `ebpf:"tcp_conn_state_map"`
	UdpConnStateMap         *ebpf.MapSpec `ebpf:"udp_conn_state_map"`
	UnusedLpmType           *ebpf.MapSpec `ebpf:"unused_lpm_type"`
	WanEgressScratchMap     *ebpf.MapSpec `ebpf:"wan_egress_scratch_map"`
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
	EventRingbuf            *ebpf.Map `ebpf:"event_ringbuf"`
	FastSock                *ebpf.Map `ebpf:"fast_sock"`
	ListenSocketMap         *ebpf.Map `ebpf:"listen_socket_map"`
	LpmArrayMap             *ebpf.Map `ebpf:"lpm_array_map"`
	OutboundConnectivityMap *ebpf.Map `ebpf:"outbound_connectivity_map"`
	RedirectTrack           *ebpf.Map `ebpf:"redirect_track"`
	RoutingHandoffMap       *ebpf.Map `ebpf:"routing_handoff_map"`
	RoutingMap              *ebpf.Map `ebpf:"routing_map"`
	RoutingMetaMap          *ebpf.Map `ebpf:"routing_meta_map"`
	TcpConnStateMap         *ebpf.Map `ebpf:"tcp_conn_state_map"`
	UdpConnStateMap         *ebpf.Map `ebpf:"udp_conn_state_map"`
	UnusedLpmType           *ebpf.Map `ebpf:"unused_lpm_type"`
	WanEgressScratchMap     *ebpf.Map `ebpf:"wan_egress_scratch_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.BpfStatsMap,
		m.CookiePidMap,
		m.DomainRoutingMap,
		m.EventRingbuf,
		m.FastSock,
		m.ListenSocketMap,
		m.LpmArrayMap,
		m.OutboundConnectivityMap,
		m.RedirectTrack,
		m.RoutingHandoffMap,
		m.RoutingMap,
		m.RoutingMetaMap,
		m.TcpConnStateMap,
		m.UdpConnStateMap,
		m.UnusedLpmType,
		m.WanEgressScratchMap,
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
	errs := make([]error, 0, len(closers))
	for _, closer := range closers {
		if closer == nil {
			continue
		}
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Additional type and function stubs for stub build

type _bpfLpmKey struct {
	PrefixLen uint32
	Data      [4]uint32
}

type bpfIfParams struct {
	RxCksmOffload                  bool
	TxL4CksmIp4Offload             bool
	TxL4CksmIp6Offload             bool
	UseNonstandardOffloadAlgorithm bool
}

type loadBpfOptions struct {
	PinPath             string
	BigEndianTproxyPort uint32
	CollectionOptions   *ebpf.CollectionOptions
}

const fastSockPlaceholderMaxEntries = 1

func fullLoadBpfObjects(
	log *logrus.Logger,
	bpf *bpfObjects,
	opts *loadBpfOptions,
	soMarkFromDae uint32,
) error {
	return errBpfObjectsUnavailable
}

func BpfMapDeleteAll[K any, V any](m *ebpf.Map) error {
	return errBpfObjectsUnavailable
}

func BpfMapBatchDelete(m *ebpf.Map, keys interface{}) (n int, err error) {
	return 0, errBpfObjectsUnavailable
}

func BpfMapBatchUpdate(m *ebpf.Map, keys interface{}, values interface{}, opts *ebpf.BatchOptions) (n int, err error) {
	return 0, errBpfObjectsUnavailable
}

func (r bpfPortRange) Encode() (b [16]byte) {
	return
}

func ParsePortRange(b []byte) (portStart, portEnd uint16) {
	return 0, 0
}

func cidrToBpfLpmKey(prefix any) _bpfLpmKey {
	return _bpfLpmKey{}
}

func (o *bpfObjects) newLpmMap(keys []_bpfLpmKey, values []uint32) (m *ebpf.Map, err error) {
	return nil, errBpfObjectsUnavailable
}

func (p bpfIfParams) CheckVersionRequirement(version any) error {
	return errBpfObjectsUnavailable
}

func detectCgroupPath() (string, error) {
	return "", errBpfObjectsUnavailable
}

func disablePinnedConnStateMaps(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return fmt.Errorf("nil collection spec")
	}
	for _, mapName := range []string{"tcp_conn_state_map", "udp_conn_state_map"} {
		m, ok := spec.Maps[mapName]
		if !ok || m == nil {
			return fmt.Errorf("missing map spec %q", mapName)
		}
		m.Pinning = ebpf.PinNone
	}
	return nil
}

func tunePlaceholderBpfMaps(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return fmt.Errorf("nil collection spec")
	}

	fastSock, ok := spec.Maps["fast_sock"]
	if !ok || fastSock == nil {
		return fmt.Errorf("missing map spec %q", "fast_sock")
	}
	fastSock.MaxEntries = fastSockPlaceholderMaxEntries
	return nil
}

func customizeBpfMapSpecs(spec *ebpf.CollectionSpec) error {
	if err := disablePinnedConnStateMaps(spec); err != nil {
		return err
	}
	if err := tunePlaceholderBpfMaps(spec); err != nil {
		return err
	}
	return nil
}

func cleanupPinnedConnStateMapFiles(log *logrus.Logger, pinPath string) int {
	if pinPath == "" {
		return 0
	}

	removed := 0
	for _, mapName := range []string{"tcp_conn_state_map", "udp_conn_state_map"} {
		path := filepath.Join(pinPath, mapName)
		if err := os.Remove(path); err != nil {
			if !os.IsNotExist(err) && log != nil {
				log.Warnf("Failed to remove stale pinned conn-state map %s: %v", mapName, err)
			}
			continue
		}
		removed++
		if log != nil {
			log.Infof("Removed stale pinned conn-state map %s", mapName)
		}
	}
	return removed
}
