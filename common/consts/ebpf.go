/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import (
	"strconv"
	"strings"

	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
)

const (
	BpfPinRoot = "/sys/fs/bpf"

	TaskCommLen = 16
)

type ParamKey uint32

const (
	ZeroKey ParamKey = iota
	BigEndianTproxyPortKey
	DisableL4TxChecksumKey
	DisableL4RxChecksumKey
	ControlPlanePidKey
	ControlPlaneNatDirectKey
	ControlPlaneDnsRoutingKey

	OneKey ParamKey = 1
)

type DisableL4ChecksumPolicy uint32

const (
	DisableL4ChecksumPolicy_EnableL4Checksum DisableL4ChecksumPolicy = iota
	DisableL4ChecksumPolicy_Restore
	DisableL4ChecksumPolicy_SetZero
)

type MatchType uint8

const (
	MatchType_DomainSet MatchType = iota
	MatchType_IpSet
	MatchType_SourceIpSet
	MatchType_Port
	MatchType_SourcePort
	MatchType_L4Proto
	MatchType_IpVersion
	MatchType_Mac
	MatchType_ProcessName
	MatchType_IfIndex
	MatchType_Dscp
	MatchType_Fallback
	MatchType_MustRules

	MatchType_Upstream
	MatchType_QType
)

type OutboundIndex uint8

const (
	OutboundDirect OutboundIndex = iota
	OutboundBlock

	OutboundUserDefinedMin

	OutboundMustRules           OutboundIndex = 0xFC
	OutboundControlPlaneRouting OutboundIndex = 0xFD
	OutboundLogicalOr           OutboundIndex = 0xFE
	OutboundLogicalAnd          OutboundIndex = 0xFF
	OutboundLogicalMask         OutboundIndex = 0xFE

	OutboundUserDefinedMax = OutboundMustRules - 1
)

func (i OutboundIndex) String() string {
	switch i {
	case OutboundMustRules:
		return "must_rules"
	case OutboundDirect:
		return "direct"
	case OutboundBlock:
		return "block"
	case OutboundControlPlaneRouting:
		return "<Control Plane Routing>"
	case OutboundLogicalOr:
		return "<OR>"
	case OutboundLogicalAnd:
		return "<AND>"
	default:
		return "<index: " + strconv.Itoa(int(i)) + ">"
	}
}

func (i OutboundIndex) IsReserved() bool {
	return !strings.HasPrefix(i.String(), "<index: ")
}

var (
	MaxMatchSetLen_ = ""
	MaxMatchSetLen  = 32 * 32
)

func init() {
	if MaxMatchSetLen_ != "" {
		i, err := strconv.Atoi(MaxMatchSetLen_)
		if err != nil {
			panic(err)
		}
		MaxMatchSetLen = i
	}
	if MaxMatchSetLen%32 != 0 {
		panic("MaxMatchSetLen should be a multiple of 32: " + strconv.Itoa(MaxMatchSetLen))
	}
}

type L4ProtoType uint8

const (
	L4ProtoType_TCP L4ProtoType = 1
	L4ProtoType_UDP L4ProtoType = 2
	L4ProtoType_X   L4ProtoType = 3
)

type IpVersionType uint8

const (
	IpVersion_4 IpVersionType = 1
	IpVersion_6 IpVersionType = 2
	IpVersion_X IpVersionType = 3
)

func (v IpVersionType) ToIpVersionStr() IpVersionStr {
	switch v {
	case IpVersion_4:
		return IpVersionStr_4
	case IpVersion_6:
		return IpVersionStr_6
	}
	panic("unsupported ipversion")
}

var (
	BasicFeatureVersion = internal.Version{5, 2, 0}
	// Deprecated: Ftrace does not support arm64 yet (Linux 6.2).
	FtraceFeatureVersion                      = internal.Version{5, 5, 0}
	UserspaceBatchUpdateFeatureVersion        = internal.Version{5, 6, 0}
	CgSocketCookieFeatureVersion              = internal.Version{5, 7, 0}
	SkAssignFeatureVersion                    = internal.Version{5, 7, 0}
	ChecksumFeatureVersion                    = internal.Version{5, 8, 0}
	ProgTypeSkLookupFeatureVersion            = internal.Version{5, 9, 0}
	SockmapFeatureVersion                     = internal.Version{5, 10, 0}
	UserspaceBatchUpdateLpmTrieFeatureVersion = internal.Version{5, 13, 0}
	BpfTimerFeatureVersion                    = internal.Version{5, 15, 0}
	HelperBpfGetFuncIpVersionFeatureVersion   = internal.Version{5, 15, 0}
	BpfLoopFeatureVersion                     = internal.Version{5, 17, 0}
)

const (
	TproxyMark       uint32 = 0x08000000
	TproxyMarkString string = "0x08000000" // Should be aligned with nftables
	Recognize        uint16 = 0x2017
	LoopbackIfIndex         = 1
)

const (
	LinkHdrLen_None     uint32 = 0
	LinkHdrLen_Ethernet uint32 = 14
)
