/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package consts

//go:generate go run ../../cmd/generators/gen_ebpf_sync

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
	TcxFeatureVersion                         = internal.Version{6, 6, 0}
	NetkitFeatureVersion                      = internal.Version{6, 7, 0}
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
