/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strconv"

	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/outbound/netproxy"
)

// PolicyIdentity returns routing metadata without retaining the normalized rule tree.
func (c *ControlPlane) PolicyIdentity() routing.PolicyIdentity {
	if c == nil {
		return routing.PolicyIdentity{}
	}
	return c.policyIdentity
}

// PolicyEpoch returns the immutable routing generation identifier.
func (c *ControlPlane) PolicyEpoch() routing.PolicyEpoch {
	return c.PolicyIdentity().Epoch()
}

// SoMarkFromDae reports the socket mark that keeps dae's own traffic out of
// its own datapath.
func (c *ControlPlane) SoMarkFromDae() uint32 {
	if c == nil {
		return 0
	}
	return c.soMarkFromDae
}

// DatapathGenerationID reports the attached eBPF datapath generation as a
// decimal string, or an empty string when this generation has no datapath.
func (c *ControlPlane) DatapathGenerationID() string {
	if c == nil || c.core == nil {
		return ""
	}
	generation := c.core.datapathGeneration.Load()
	if generation == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(generation), 10)
}

// DirectDialer returns the generation-scoped direct dialer. A probe uses it to
// reach a node's own server address without going through that node.
func (c *ControlPlane) DirectDialer() netproxy.Dialer {
	if c == nil {
		return nil
	}
	return c.directDialer
}

// EgressDialers returns every node dialer this generation manages, including
// nodes no group currently selects, in a stable order.
func (c *ControlPlane) EgressDialers() []*dialer.Dialer {
	if c == nil || c.egressRuntime == nil {
		return nil
	}
	return c.egressRuntime.dialers()
}

// NodeParseReport reports, per subscription tag, how many links this generation
// received and how many of them became dialers. The reload caller uses it to
// keep the previous generation when a fetched payload produced no usable node,
// and to avoid persisting such a payload over the last good cached copy.
func (c *ControlPlane) NodeParseReport() map[string]outbound.NodeParseCount {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.nodeParseReport
}

// OutboundGroups returns this generation's outbounds in outbound-ID order,
// including the builtin direct and block groups. The slice is immutable once
// the generation is published, so callers must not modify it.
func (c *ControlPlane) OutboundGroups() []*outbound.DialerGroup {
	if c == nil {
		return nil
	}
	return c.outbounds
}

// RollbackPreparedRoutingEpoch restores the previously active kernel plan
// before a failed prepared generation releases its slot-owned resources.
func (c *ControlPlane) RollbackPreparedRoutingEpoch() error {
	if c == nil || c.core == nil {
		return nil
	}
	if err := c.rollbackRoutingEpoch(); err != nil {
		return err
	}
	if c.bpfMaintenance != nil {
		return c.bpfMaintenance.rollback()
	}
	return nil
}

//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -cc "$BPF_CLANG" "$BPF_STRIP_FLAG" -cflags "$BPF_CFLAGS" -tags "!dae_stub_ebpf" -target "$BPF_TARGET" -type port_range -type tuples_key -type conn_state bpf kern/tproxy.c -- -I./headers
//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -cc "$BPF_CLANG" "$BPF_STRIP_FLAG" -cflags "$BPF_CFLAGS" -tags "!dae_stub_ebpf" -target "$BPF_TARGET" directstats kern/direct_stats.c -- -I./headers
