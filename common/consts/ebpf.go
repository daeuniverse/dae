/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */

package consts

import internal "github.com/v2rayA/dae/pkg/ebpf_internal"

const (
	AppName    = "dae"
	BpfPinRoot = "/sys/fs/bpf"

	AddrHdrSize = 20

	TaskCommLen = 16
)

type ParamKey uint32

const (
	ZeroKey ParamKey = iota
	BigEndianTproxyPortKey
	DisableL4TxChecksumKey
	DisableL4RxChecksumKey
	ControlPlaneOidKey
)

type DisableL4ChecksumPolicy uint32

const (
	DisableL4ChecksumPolicy_EnableL4Checksum DisableL4ChecksumPolicy = iota
	DisableL4ChecksumPolicy_Restore
	DisableL4ChecksumPolicy_SetZero
)

type RoutingType uint8

const (
	MatchType_DomainSet RoutingType = iota
	MatchType_IpSet
	MatchType_SourceIpSet
	MatchType_Port
	MatchType_SourcePort
	MatchType_L4Proto
	MatchType_IpVersion
	MatchType_Mac
	MatchType_ProcessName
	MatchType_Final
)

type OutboundIndex uint8

const (
	OutboundDirect             OutboundIndex = 0
	OutboundBlock              OutboundIndex = 1
	OutboundControlPlaneDirect OutboundIndex = 0xFD
	OutboundLogicalOr          OutboundIndex = 0xFE
	OutboundLogicalAnd         OutboundIndex = 0xFF
)

func (i OutboundIndex) String() string {
	switch i {
	case OutboundDirect:
		return "direct"
	case OutboundBlock:
		return "block"
	case OutboundControlPlaneDirect:
		return "<Control Plane Direct>"
	case OutboundLogicalOr:
		return "<OR>"
	case OutboundLogicalAnd:
		return "<AND>"
	default:
		return ""
	}
}

const (
	MaxMatchSetLen = 32 * 3
)

type L4ProtoType uint8

const (
	L4ProtoType_TCP     L4ProtoType = 1
	L4ProtoType_UDP     L4ProtoType = 2
	L4ProtoType_TCP_UDP L4ProtoType = 3
)

type IpVersionType uint8

const (
	IpVersion_4 IpVersionType = 1
	IpVersion_6 IpVersionType = 2
	IpVersion_X IpVersionType = 3
)

var BasicFeatureVersion = internal.Version{5, 2, 0}
var FtraceFeatureVersion = internal.Version{5, 5, 0}
var CgGetPidFeatureVersion = internal.Version{5, 7, 0}
