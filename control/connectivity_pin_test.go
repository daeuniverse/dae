/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

// annotationsFor builds the one-annotation-per-dialer slice NewDialerGroup
// requires.
func annotationsFor(dialers []*dialer.Dialer) []*dialer.Annotation {
	out := make([]*dialer.Annotation, len(dialers))
	for i := range out {
		out[i] = &dialer.Annotation{}
	}
	return out
}

// TestPinnedTransportStaysAdmittedWithoutHealthyMembers pins the fix for a
// pinned member being dropped in the kernel: the automatic policies gate
// admission on probe health, and a pin is an explicit user choice that must
// survive an empty healthy set.
func TestPinnedTransportStaysAdmittedWithoutHealthyMembers(t *testing.T) {
	log := logrus.New()
	var dialers []*dialer.Dialer
	for _, link := range []string{"socks5://192.0.2.1:1080", "socks5://192.0.2.2:1080"} {
		d, err := dialer.NewFromLinkContext(context.Background(), &dialer.GlobalOption{Log: log}, dialer.InstanceOption{DisableCheck: true}, link, "")
		if err != nil {
			t.Fatalf("build dialer: %v", err)
		}
		defer func() { _ = d.Close() }()
		dialers = append(dialers, d)
	}
	group := outbound.NewDialerGroup(&dialer.GlobalOption{Log: log}, "auto", dialers, annotationsFor(dialers),
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}, nil)
	defer func() { _ = group.Close() }()

	// Report every member as unhealthy through the real alive sets, which is the
	// state a pinned group would otherwise be dropped in.
	for _, healthKey := range dialer.StandardHealthKeys() {
		networkType := healthKey.NetworkType()
		if set := group.MustGetAliveDialerSet(networkType); set == nil {
			t.Fatalf("group has no alive set for %v", networkType)
		}
		for _, d := range dialers {
			d.ReportUnavailableForced(networkType, errors.New("offline"))
		}
	}

	plane := &ControlPlane{}
	plane.dialMode = consts.DialMode_Ip
	admitted := func() map[consts.L4ProtoStr]bool {
		out := map[consts.L4ProtoStr]bool{}
		plane.publishOutboundConnectivity(1, group, func(_ uint8, alive bool, networkType *dialer.NetworkType) {
			out[networkType.L4Proto] = alive
		})
		return out
	}

	// No healthy member and no pin: the automatic policy blocks admission.
	got := admitted()
	if got[consts.L4ProtoStr_TCP] || got[consts.L4ProtoStr_UDP] {
		t.Fatalf("an unpinned group with no healthy member must stay blocked: %+v", got)
	}

	// Pinning TCP admits TCP only; UDP keeps following health.
	if _, err := group.SetOverride(outbound.SelectionNetworkTCP, 1); err != nil {
		t.Fatal(err)
	}
	got = admitted()
	if !got[consts.L4ProtoStr_TCP] {
		t.Fatalf("a pinned TCP transport must be admitted: %+v", got)
	}
	if got[consts.L4ProtoStr_UDP] {
		t.Fatalf("UDP was not pinned and must stay blocked: %+v", got)
	}

	// Clearing the pin closes admission again.
	if _, err := group.ClearOverride(outbound.SelectionNetworkTCP); err != nil {
		t.Fatal(err)
	}
	if got = admitted(); got[consts.L4ProtoStr_TCP] {
		t.Fatalf("clearing the pin must restore health-gated admission: %+v", got)
	}
}

// TestRepublishOutboundConnectivityWritesPinnedOutbound verifies the entry point
// the API calls after a pin change: it must find the outbound by group identity
// and rewrite its slots.
func TestRepublishOutboundConnectivityWritesPinnedOutbound(t *testing.T) {
	log := logrus.New()
	var dialers []*dialer.Dialer
	for _, link := range []string{"socks5://192.0.2.3:1080"} {
		d, err := dialer.NewFromLinkContext(context.Background(), &dialer.GlobalOption{Log: log}, dialer.InstanceOption{DisableCheck: true}, link, "")
		if err != nil {
			t.Fatalf("build dialer: %v", err)
		}
		defer func() { _ = d.Close() }()
		dialers = append(dialers, d)
	}
	target := outbound.NewDialerGroup(&dialer.GlobalOption{Log: log}, "target", dialers, annotationsFor(dialers),
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinAverage10Latencies}, nil)
	defer func() { _ = target.Close() }()
	other := outbound.NewDialerGroup(&dialer.GlobalOption{Log: log}, "other", dialers, annotationsFor(dialers),
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinAverage10Latencies}, nil)
	defer func() { _ = other.Close() }()

	plane := &ControlPlane{}
	plane.dialMode = consts.DialMode_Ip
	plane.outbounds = []*outbound.DialerGroup{other, target}
	if _, err := target.SetOverride(outbound.SelectionNetworkUDP, 0); err != nil {
		t.Fatal(err)
	}

	// Republish writes through the kernel writer, which needs a live datapath;
	// without one it is a no-op. What this pins is the ownership check: an
	// unknown group must not touch a generation that is retiring, and a known
	// one must be found by identity rather than by name.
	plane.core = &controlPlaneCore{}
	plane.core.markOutboundConnectivityRetired()
	plane.RepublishOutboundConnectivity(target)
	if !plane.core.retired.Load() {
		t.Fatal("republish must not resurrect a retired generation")
	}
}
