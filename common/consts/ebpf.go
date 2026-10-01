/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
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

	OneKey ParamKey = 1
	TwoKey ParamKey = 2
)

func (i OutboundIndex) String() string {
	switch i {
	case OutboundMustRules:
		return "must_rules"
	case OutboundDirect:
		return "direct"
	case OutboundBlock:
		return "block"
	case OutboundReject:
		return "reject"
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
	UserspaceBatchUpdateFeatureVersion        = internal.Version{5, 6, 0}
	SkAssignFeatureVersion                    = internal.Version{5, 7, 0}
	ChecksumFeatureVersion                    = internal.Version{5, 8, 0}
	UserspaceBatchUpdateLpmTrieFeatureVersion = internal.Version{5, 13, 0}
	BpfTimerFeatureVersion                    = internal.Version{5, 15, 0}
	HelperBpfGetFuncIpVersionFeatureVersion   = internal.Version{5, 15, 0}
	BpfLoopFeatureVersion                     = internal.Version{5, 17, 0}
	NetkitFeatureVersion                      = internal.Version{6, 7, 0}
	// RedirectPeerSafeVersion is the mainline kernel version that fixed
	// CVE-2025-37959 ("bpf: Scrub packet on bpf_redirect_peer"): stale skb
	// metadata could be exposed when bpf_redirect_peer() crossed a netns
	// boundary. Fixed in mainline 6.14.7 / 6.15-rc6.
	// See https://cve.org/CVERecord?id=CVE-2025-37959.
	RedirectPeerSafeVersion = internal.Version{6, 14, 7}
	// RedirectPeerCveFixedStable lists the official stable backports of the
	// CVE-2025-37959 fix (per the linux-cve-announce notification). Distro
	// backports to other versions cannot be detected by version alone; opt in
	// with the DAE_ALLOW_REDIRECT_PEER=1 environment variable.
	RedirectPeerCveFixedStable = []internal.Version{
		{6, 1, 139},
		{6, 6, 91},
		{6, 12, 29},
	}
	// TcpSockmapPanicSafeVersion is the mainline kernel version that fixed
	// CVE-2025-38165 ("bpf, sockmap: Fix panic when calling skb_linearize"):
	// a message larger than MAX_MSG_FRAGS redirected into a sockmap ingress
	// queue hit BUG_ON(skb_shared(skb)) in skb_linearize. This is the panic
	// class that forced upstream dae to disable its sockmap fast redirect.
	// See https://cve.org/CVERecord?id=CVE-2025-38165.
	TcpSockmapPanicSafeVersion = internal.Version{6, 15, 3}
	// TcpSockmapPanicFixedStable lists the official stable backports of the
	// CVE-2025-38165 fix (per the linux-cve-announce notification). Distro
	// backports to other versions cannot be detected by version alone; opt in
	// with the DAE_ALLOW_TCP_SOCKMAP=1 environment variable.
	TcpSockmapPanicFixedStable = []internal.Version{
		{6, 1, 142},
		{6, 6, 94},
		{6, 12, 34},
	}
)

// IsRedirectPeerSafeKernel reports whether the kernel is known to contain the
// CVE-2025-37959 fix (mainline 6.14.7+ or an official stable backport).
func IsRedirectPeerSafeKernel(v internal.Version) bool {
	if !v.Less(RedirectPeerSafeVersion) {
		return true
	}
	for _, stable := range RedirectPeerCveFixedStable {
		if v[0] == stable[0] && v[1] == stable[1] && v[2] >= stable[2] {
			return true
		}
	}
	return false
}

// IsTcpSockmapPanicSafeKernel reports whether the kernel is known to contain the
// CVE-2025-38165 fix (mainline 6.15.3+ or an official stable backport). Only
// kernels passing this gate enable the TCP relay eBPF offload by default.
func IsTcpSockmapPanicSafeKernel(v internal.Version) bool {
	if !v.Less(TcpSockmapPanicSafeVersion) {
		return true
	}
	for _, stable := range TcpSockmapPanicFixedStable {
		if v[0] == stable[0] && v[1] == stable[1] && v[2] >= stable[2] {
			return true
		}
	}
	return false
}

const (
	TproxyMark      uint32 = 0x08000000
	LoopbackIfIndex int    = 1
)

const (
	LinkHdrLen_None     uint32 = 0
	LinkHdrLen_Ethernet uint32 = 14
)
