/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package consts

const (
	AppName           = "dae"
	MaxInterfaceIpNum = 8
	BpfPinRoot        = "/sys/fs/bpf"

	AddrHdrSize = 20
)

type ParamKey uint32

const (
	ZeroKey ParamKey = iota
	BigEndianTproxyPortKey
	DisableL4TxChecksumKey
	DisableL4RxChecksumKey
	EpochKey
	RoutingsLenKey
)

type DisableL4ChecksumPolicy uint32

const (
	DisableL4ChecksumPolicy_EnableL4Checksum DisableL4ChecksumPolicy = iota
	DisableL4ChecksumPolicy_Restore
	DisableL4ChecksumPolicy_SetZero
)

type RoutingType uint32

const (
	RoutingType_DomainSet RoutingType = iota
	RoutingType_IpSet
	RoutingType_SourceIpSet
	RoutingType_Port
	RoutingType_SourcePort
	RoutingType_Network
	RoutingType_IpVersion
	RoutingType_Mac
	RoutingType_Final
)

type OutboundIndex uint8

const (
	OutboundDirect             OutboundIndex = 0
	OutboundControlPlaneDirect OutboundIndex = 0xFE
	OutboundLogicalAnd         OutboundIndex = 0xFF
)

func (i OutboundIndex) String() string {
	switch i {
	case OutboundDirect:
		return "direct"
	case OutboundControlPlaneDirect:
		return "<Control Plane Direct>"
	case OutboundLogicalAnd:
		return "<AND>"
	default:
		return ""
	}
}

const (
	MaxRoutingLen = 96
)

type NetworkType uint8

const (
	NetworkType_TCP     NetworkType = 1
	NetworkType_UDP     NetworkType = 2
	NetworkType_TCP_UDP NetworkType = 3
)

type IpVersion uint8

const (
	IpVersion_4 IpVersion = 1
	IpVersion_6 IpVersion = 2
	IpVersion_X IpVersion = 3
)
