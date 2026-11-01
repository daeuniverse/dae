//go:build dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"structs"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
)

var errBpfObjectsUnavailable = errors.New("eBPF objects are unavailable in this build; this is a stub build (tag dae_stub_ebpf); run make ebpf before building")

// bpfDaeParam corresponds to C struct dae_param in tproxy.c
// use_redirect_peer enables bpf_redirect_peer() optimization for TC ingress.
// Only safe with: (1) netkit device + scrub=NONE, (2) a kernel containing the
// CVE-2025-37959 fix (mainline >= 6.14.7 or official stable backports).
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
	DatapathGeneration   uint16
	DaeSocketMark        uint32 // mark set on dae's own sockets to identify them in eBPF
}

type bpfDomainRouting struct {
	_      structs.HostLayout
	Bitmap [32]uint32
}

type bpfRoutingEpochIp struct {
	_    structs.HostLayout
	Slot uint32
	Addr [4]uint32
}

type bpfMatchSet struct {
	_        structs.HostLayout
	Value    [16]uint8
	Not      uint8
	Type     uint8
	Outbound uint8
	Must     uint8
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
	_                  structs.HostLayout
	Mark               uint32
	Must               uint8
	Mac                [6]uint8
	Outbound           uint8
	Pname              [16]uint8
	Pid                uint32
	Dscp               uint8
	RoutingEpochSlot   uint8
	DatapathGeneration uint16
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

type bpfConnState struct {
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
	Mac                [6]uint8
	_                  [2]byte
	Pname              [16]uint8
	Pid                uint32
	RoutingEpochSlot   uint8
	PaddingAfterPid    uint8
	DatapathGeneration uint16
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

func loadBpfObjects(_ any, _ *ebpf.CollectionOptions) error {
	return errBpfObjectsUnavailable
}

type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
	bpfVariableSpecs
}

type bpfProgramSpecs struct {
	TproxyDae0Ingress           *ebpf.ProgramSpec `ebpf:"tproxy_dae0_ingress"`
	TproxyDae0peerIngress       *ebpf.ProgramSpec `ebpf:"tproxy_dae0peer_ingress"`
	TproxyLanEgressL2           *ebpf.ProgramSpec `ebpf:"tproxy_lan_egress_l2"`
	TproxyLanEgressL3           *ebpf.ProgramSpec `ebpf:"tproxy_lan_egress_l3"`
	TproxyLanIngressL2          *ebpf.ProgramSpec `ebpf:"tproxy_lan_ingress_l2"`
	TproxyLanIngressL3          *ebpf.ProgramSpec `ebpf:"tproxy_lan_ingress_l3"`
	TproxyLanWanEgressL2        *ebpf.ProgramSpec `ebpf:"tproxy_lan_wan_egress_l2"`
	TproxyLanWanEgressL3        *ebpf.ProgramSpec `ebpf:"tproxy_lan_wan_egress_l3"`
	TcpOffloadRedirect          *ebpf.ProgramSpec `ebpf:"tcp_offload_redirect"`
	TcpOffloadSentAccount       *ebpf.ProgramSpec `ebpf:"tcp_offload_sent_account"`
	TcpOffloadSentAccountKprobe *ebpf.ProgramSpec `ebpf:"tcp_offload_sent_account_kprobe"`
	TproxyWanCgConnect4         *ebpf.ProgramSpec `ebpf:"tproxy_wan_cg_connect4"`
	TproxyWanCgConnect6         *ebpf.ProgramSpec `ebpf:"tproxy_wan_cg_connect6"`
	TproxyWanCgSendmsg4         *ebpf.ProgramSpec `ebpf:"tproxy_wan_cg_sendmsg4"`
	TproxyWanCgSendmsg6         *ebpf.ProgramSpec `ebpf:"tproxy_wan_cg_sendmsg6"`
	TproxyWanCgSockCreate       *ebpf.ProgramSpec `ebpf:"tproxy_wan_cg_sock_create"`
	TproxyWanCgSockRelease      *ebpf.ProgramSpec `ebpf:"tproxy_wan_cg_sock_release"`
	TproxyWanEgressL2           *ebpf.ProgramSpec `ebpf:"tproxy_wan_egress_l2"`
	TproxyWanEgressL3           *ebpf.ProgramSpec `ebpf:"tproxy_wan_egress_l3"`
	TproxyWanIngressL2          *ebpf.ProgramSpec `ebpf:"tproxy_wan_ingress_l2"`
	TproxyWanIngressL3          *ebpf.ProgramSpec `ebpf:"tproxy_wan_ingress_l3"`
	TproxyWanLanIngressL2       *ebpf.ProgramSpec `ebpf:"tproxy_wan_lan_ingress_l2"`
	TproxyWanLanIngressL3       *ebpf.ProgramSpec `ebpf:"tproxy_wan_lan_ingress_l3"`
}

type bpfMapSpecs struct {
	ActiveRoutingEpochMap    *ebpf.MapSpec `ebpf:"active_routing_epoch_map"`
	AliveBlockRateMap        *ebpf.MapSpec `ebpf:"alive_block_rate_map"`
	BpfStatsMap              *ebpf.MapSpec `ebpf:"bpf_stats_map"`
	ConntrackArgsMap         *ebpf.MapSpec `ebpf:"conntrack_args_map"`
	CookiePidMap             *ebpf.MapSpec `ebpf:"cookie_pid_map"`
	DaeIfindexMap            *ebpf.MapSpec `ebpf:"dae_ifindex_map"`
	DomainRoutingMap         *ebpf.MapSpec `ebpf:"domain_routing_map"`
	EventRingbuf             *ebpf.MapSpec `ebpf:"event_ringbuf"`
	FastSock                 *ebpf.MapSpec `ebpf:"fast_sock"`
	TcpOffloadPause          *ebpf.MapSpec `ebpf:"tcp_offload_pause"`
	TcpOffloadSent           *ebpf.MapSpec `ebpf:"tcp_offload_sent"`
	ListenSocketMap          *ebpf.MapSpec `ebpf:"listen_socket_map"`
	LpmArrayMap              *ebpf.MapSpec `ebpf:"lpm_array_map"`
	OutboundConnectivityMap  *ebpf.MapSpec `ebpf:"outbound_connectivity_map"`
	ParseCtxScratchMap       *ebpf.MapSpec `ebpf:"parse_ctx_scratch_map"`
	RedirectTrack            *ebpf.MapSpec `ebpf:"redirect_track"`
	RouteCtxScratchMap       *ebpf.MapSpec `ebpf:"route_ctx_scratch_map"`
	RoutingHandoffMap        *ebpf.MapSpec `ebpf:"routing_handoff_map"`
	RoutingMap               *ebpf.MapSpec `ebpf:"routing_map"`
	RoutingMetaMap           *ebpf.MapSpec `ebpf:"routing_meta_map"`
	ConnStateMap             *ebpf.MapSpec `ebpf:"conn_state_map"`
	UnusedLpmType            *ebpf.MapSpec `ebpf:"unused_lpm_type"`
	WanEgressRouteScratchMap *ebpf.MapSpec `ebpf:"wan_egress_route_scratch_map"`
	PktScratchMap            *ebpf.MapSpec `ebpf:"pkt_scratch_map"`
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
	ActiveRoutingEpochMap    *ebpf.Map `ebpf:"active_routing_epoch_map"`
	AliveBlockRateMap        *ebpf.Map `ebpf:"alive_block_rate_map"`
	BpfStatsMap              *ebpf.Map `ebpf:"bpf_stats_map"`
	ConntrackArgsMap         *ebpf.Map `ebpf:"conntrack_args_map"`
	CookiePidMap             *ebpf.Map `ebpf:"cookie_pid_map"`
	DaeIfindexMap            *ebpf.Map `ebpf:"dae_ifindex_map"`
	DomainRoutingMap         *ebpf.Map `ebpf:"domain_routing_map"`
	EventRingbuf             *ebpf.Map `ebpf:"event_ringbuf"`
	FastSock                 *ebpf.Map `ebpf:"fast_sock"`
	TcpOffloadPause          *ebpf.Map `ebpf:"tcp_offload_pause"`
	TcpOffloadSent           *ebpf.Map `ebpf:"tcp_offload_sent"`
	ListenSocketMap          *ebpf.Map `ebpf:"listen_socket_map"`
	LpmArrayMap              *ebpf.Map `ebpf:"lpm_array_map"`
	OutboundConnectivityMap  *ebpf.Map `ebpf:"outbound_connectivity_map"`
	ParseCtxScratchMap       *ebpf.Map `ebpf:"parse_ctx_scratch_map"`
	RedirectTrack            *ebpf.Map `ebpf:"redirect_track"`
	RouteCtxScratchMap       *ebpf.Map `ebpf:"route_ctx_scratch_map"`
	RoutingHandoffMap        *ebpf.Map `ebpf:"routing_handoff_map"`
	RoutingMap               *ebpf.Map `ebpf:"routing_map"`
	RoutingMetaMap           *ebpf.Map `ebpf:"routing_meta_map"`
	ConnStateMap             *ebpf.Map `ebpf:"conn_state_map"`
	UnusedLpmType            *ebpf.Map `ebpf:"unused_lpm_type"`
	WanEgressRouteScratchMap *ebpf.Map `ebpf:"wan_egress_route_scratch_map"`
	PktScratchMap            *ebpf.Map `ebpf:"pkt_scratch_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.ActiveRoutingEpochMap,
		m.AliveBlockRateMap,
		m.BpfStatsMap,
		m.ConntrackArgsMap,
		m.CookiePidMap,
		m.DaeIfindexMap,
		m.DomainRoutingMap,
		m.EventRingbuf,
		m.FastSock,
		m.TcpOffloadPause,
		m.TcpOffloadSent,
		m.ListenSocketMap,
		m.LpmArrayMap,
		m.OutboundConnectivityMap,
		m.ParseCtxScratchMap,
		m.RedirectTrack,
		m.RouteCtxScratchMap,
		m.RoutingHandoffMap,
		m.RoutingMap,
		m.RoutingMetaMap,
		m.ConnStateMap,
		m.UnusedLpmType,
		m.WanEgressRouteScratchMap,
		m.PktScratchMap,
	)
}

type bpfVariables struct {
	PARAM *ebpf.Variable `ebpf:"PARAM"`
}

type bpfPrograms struct {
	TproxyDae0Ingress           *ebpf.Program `ebpf:"tproxy_dae0_ingress"`
	TproxyDae0peerIngress       *ebpf.Program `ebpf:"tproxy_dae0peer_ingress"`
	TproxyLanEgressL2           *ebpf.Program `ebpf:"tproxy_lan_egress_l2"`
	TproxyLanEgressL3           *ebpf.Program `ebpf:"tproxy_lan_egress_l3"`
	TproxyLanIngressL2          *ebpf.Program `ebpf:"tproxy_lan_ingress_l2"`
	TproxyLanIngressL3          *ebpf.Program `ebpf:"tproxy_lan_ingress_l3"`
	TproxyLanWanEgressL2        *ebpf.Program `ebpf:"tproxy_lan_wan_egress_l2"`
	TproxyLanWanEgressL3        *ebpf.Program `ebpf:"tproxy_lan_wan_egress_l3"`
	TcpOffloadRedirect          *ebpf.Program `ebpf:"tcp_offload_redirect"`
	TcpOffloadSentAccount       *ebpf.Program `ebpf:"tcp_offload_sent_account"`
	TcpOffloadSentAccountKprobe *ebpf.Program `ebpf:"tcp_offload_sent_account_kprobe"`
	TproxyWanCgConnect4         *ebpf.Program `ebpf:"tproxy_wan_cg_connect4"`
	TproxyWanCgConnect6         *ebpf.Program `ebpf:"tproxy_wan_cg_connect6"`
	TproxyWanCgSendmsg4         *ebpf.Program `ebpf:"tproxy_wan_cg_sendmsg4"`
	TproxyWanCgSendmsg6         *ebpf.Program `ebpf:"tproxy_wan_cg_sendmsg6"`
	TproxyWanCgSockCreate       *ebpf.Program `ebpf:"tproxy_wan_cg_sock_create"`
	TproxyWanCgSockRelease      *ebpf.Program `ebpf:"tproxy_wan_cg_sock_release"`
	TproxyWanEgressL2           *ebpf.Program `ebpf:"tproxy_wan_egress_l2"`
	TproxyWanEgressL3           *ebpf.Program `ebpf:"tproxy_wan_egress_l3"`
	TproxyWanIngressL2          *ebpf.Program `ebpf:"tproxy_wan_ingress_l2"`
	TproxyWanIngressL3          *ebpf.Program `ebpf:"tproxy_wan_ingress_l3"`
	TproxyWanLanIngressL2       *ebpf.Program `ebpf:"tproxy_wan_lan_ingress_l2"`
	TproxyWanLanIngressL3       *ebpf.Program `ebpf:"tproxy_wan_lan_ingress_l3"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.TproxyDae0Ingress,
		p.TproxyDae0peerIngress,
		p.TproxyLanEgressL2,
		p.TproxyLanEgressL3,
		p.TproxyLanIngressL2,
		p.TproxyLanIngressL3,
		p.TproxyLanWanEgressL2,
		p.TproxyLanWanEgressL3,
		p.TcpOffloadRedirect,
		p.TcpOffloadSentAccount,
		p.TcpOffloadSentAccountKprobe,
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
		p.TproxyWanLanIngressL2,
		p.TproxyWanLanIngressL3,
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
	PinPath                    string
	BigEndianTproxyPort        uint32
	CollectionOptions          *ebpf.CollectionOptions
	ConnStateMapMaxEntries     uint32
	RedirectTrackMapMaxEntries uint32
	DatapathGeneration         uint16
}

const (
	defaultConnStateMapMaxEntries = 65536 * 4
	// Mirrors MAX_REDIRECT_TRACK_NUM in kern/tproxy.c; see bpf_utils.go for
	// the single-owner contract with tuneRedirectTrackMap.
	defaultRedirectTrackMapMaxEntries = 65536
)

func fullLoadBpfObjects(
	log *logrus.Logger,
	bpf *bpfObjects,
	opts *loadBpfOptions,
	soMarkFromDae uint32,
) error {
	return errBpfObjectsUnavailable
}

// logRemovedIncompatiblePinnedMap has no counterpart in this build: the stub
// loader never loads objects and never removes a pinned map, so the warning it
// emits (bpf_utils.go) is unreachable here. The stub exists so the shared
// source-contract tests that reference the symbol still compile.
func logRemovedIncompatiblePinnedMap(_ *logrus.Logger, _, _ string) {}

func BpfMapDeleteAll[K any, V any](m *ebpf.Map) error {
	return errBpfObjectsUnavailable
}

func BpfMapBatchDeleteAll[K any, V any](m *ebpf.Map) error {
	return errBpfObjectsUnavailable
}

func BpfMapBatchDelete(m *ebpf.Map, keys any) (n int, err error) {
	return 0, errBpfObjectsUnavailable
}

func BpfMapBatchUpdate(m *ebpf.Map, keys any, values any, opts *ebpf.BatchOptions) (n int, err error) {
	return 0, errBpfObjectsUnavailable
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
	m, ok := spec.Maps["conn_state_map"]
	if !ok || m == nil {
		return fmt.Errorf("missing map spec %q", "conn_state_map")
	}
	m.Pinning = ebpf.PinNone
	return nil
}

func tuneConnStateBpfMap(spec *ebpf.CollectionSpec, maxEntries uint32) error {
	if spec == nil {
		return fmt.Errorf("nil collection spec")
	}
	if maxEntries == 0 {
		maxEntries = defaultConnStateMapMaxEntries
	}
	connState, ok := spec.Maps["conn_state_map"]
	if !ok || connState == nil {
		return fmt.Errorf("missing map spec %q", "conn_state_map")
	}
	connState.MaxEntries = maxEntries
	return nil
}

func tuneRedirectTrackMap(spec *ebpf.CollectionSpec, maxEntries uint32) error {
	if spec == nil {
		return fmt.Errorf("nil collection spec")
	}
	if maxEntries == 0 {
		maxEntries = defaultRedirectTrackMapMaxEntries
	}
	m, ok := spec.Maps["redirect_track"]
	if !ok || m == nil {
		return fmt.Errorf("missing map spec %q", "redirect_track")
	}
	if m.MaxEntries != maxEntries {
		return fmt.Errorf("redirect_track capacity %d diverges from the expected %d (MAX_REDIRECT_TRACK_NUM in kern/tproxy.c and defaultRedirectTrackMapMaxEntries in bpf_utils.go must agree)",
			m.MaxEntries, maxEntries)
	}
	m.MaxEntries = maxEntries
	return nil
}

func customizeBpfMapSpecs(spec *ebpf.CollectionSpec, connStateMapMaxEntries, redirectTrackMapMaxEntries uint32) error {
	if err := disablePinnedConnStateMaps(spec); err != nil {
		return err
	}
	if err := tuneConnStateBpfMap(spec, connStateMapMaxEntries); err != nil {
		return err
	}
	return tuneRedirectTrackMap(spec, redirectTrackMapMaxEntries)
}

func cleanupPinnedConnStateMapFiles(log *logrus.Logger, pinPath string) int {
	if pinPath == "" {
		return 0
	}

	removed := 0
	for _, mapName := range []string{"conn_state_map", "tcp_conn_state_map", "udp_conn_state_map"} {
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

func cleanupEphemeralBpfPinDirs(log *logrus.Logger, pinPath string) int {
	if pinPath == "" {
		return 0
	}
	entries, err := os.ReadDir(pinPath)
	if err != nil {
		if !os.IsNotExist(err) && log != nil {
			log.Warnf("Failed to read BPF pin path %s: %v", pinPath, err)
		}
		return 0
	}

	removed := 0
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "reload-") {
			continue
		}
		path := filepath.Join(pinPath, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			if log != nil {
				log.Warnf("Failed to remove stale reload BPF pin directory %s: %v", entry.Name(), err)
			}
			continue
		}
		removed++
		if log != nil {
			log.Infof("Removed stale reload BPF pin directory %s", entry.Name())
		}
	}
	return removed
}
