/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func newConnectivitySnapshotTestPlane(t *testing.T, mode consts.DialMode, policy consts.DialerSelectionPolicy) (*ControlPlane, *outbound.DialerGroup, []*dialer.Dialer) {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	option := &dialer.GlobalOption{Log: log, CheckInterval: time.Minute}
	dialers := make([]*dialer.Dialer, 2)
	for i := range dialers {
		d := dialer.NewDialerContext(context.Background(), nil, option, dialer.InstanceOption{DisableCheck: true}, &dialer.Property{})
		dialers[i] = d
		t.Cleanup(func() { _ = d.Close() })
	}
	group := outbound.NewDialerGroup(option, "snapshot", dialers, []*dialer.Annotation{{}, {}}, outbound.DialerSelectionPolicy{Policy: policy}, func(bool, *dialer.NetworkType, bool) {})
	t.Cleanup(func() { _ = group.Close() })
	plane := &ControlPlane{
		core: &controlPlaneCore{},
		controlPlaneGenerationState: controlPlaneGenerationState{
			dialMode:  mode,
			outbounds: []*outbound.DialerGroup{nil, group},
		},
	}
	return plane, group, dialers
}

func TestConnectivitySnapshotPreservesAdmissionPolicy(t *testing.T) {
	for _, mode := range []consts.DialMode{consts.DialMode_Ip, consts.DialMode_Domain, consts.DialMode_DomainPlus, consts.DialMode_DomainCao} {
		for _, policy := range []consts.DialerSelectionPolicy{
			consts.DialerSelectionPolicy_Random,
			consts.DialerSelectionPolicy_Fixed,
			consts.DialerSelectionPolicy_MinLastLatency,
			consts.DialerSelectionPolicy_MinAverage10Latencies,
			consts.DialerSelectionPolicy_MinMovingAverageLatencies,
		} {
			t.Run(string(mode)+"/"+string(policy), func(t *testing.T) {
				plane, _, dialers := newConnectivitySnapshotTestPlane(t, mode, policy)
				healthKeys := dialer.StandardHealthKeys()
				for _, key := range healthKeys {
					for _, d := range dialers {
						d.ReportUnavailableForced(key.NetworkType(), stderrors.New("offline"))
					}
				}
				optimistic := mode != consts.DialMode_Ip || policy == consts.DialerSelectionPolicy_Random || policy == consts.DialerSelectionPolicy_Fixed
				published := make(map[uint32]bool)
				publish := func(id uint8, alive bool, nt *dialer.NetworkType) {
					published[outboundConnectivityMapKey(id, nt)] = alive
				}
				plane.PauseOutboundConnectivityUpdates()
				plane.resumeOutboundConnectivityUpdates(publish)
				if len(published) != len(healthKeys) {
					t.Fatalf("published %d slots, want six non-nil-group slots", len(published))
				}
				for slot, alive := range published {
					if alive != optimistic {
						t.Errorf("empty slot %d=%v, want admission=%v", slot, alive, optimistic)
					}
				}
				revived := dialer.HealthKey{Domain: dialer.HealthDomainDataUDP, IpVersion: consts.IpVersionStr_4}
				dialers[0].ReportAvailableTraffic(revived.NetworkType())
				plane.PauseOutboundConnectivityUpdates()
				plane.resumeOutboundConnectivityUpdates(publish)
				for _, key := range healthKeys {
					want := optimistic || key == revived
					if got := published[outboundConnectivityMapKey(1, key.NetworkType())]; got != want {
						t.Errorf("revived snapshot %v=%v, want %v", key, got, want)
					}
				}
				plane.core.markOutboundConnectivityRetired()
				plane.resumeOutboundConnectivityUpdates(func(uint8, bool, *dialer.NetworkType) {
					t.Error("retired generation published a snapshot")
				})
			})
		}
	}
}

func TestConnectivitySnapshotKeepsRandomUDPFallbackReachable(t *testing.T) {
	plane, group, dialers := newConnectivitySnapshotTestPlane(t, consts.DialMode_Ip, consts.DialerSelectionPolicy_Random)
	data := &dialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, UdpHealthDomain: dialer.UdpHealthDomainData}
	for _, d := range dialers {
		d.ReportUnavailableForced(data, stderrors.New("data UDP unavailable"))
	}
	if selected, _, err := group.Select(data, true); err != nil || selected == nil {
		t.Fatalf("expected existing DNS UDP fallback: selected=%v err=%v", selected, err)
	}
	// A failed successor may have written zero into the shared map. The old
	// generation must restore admission, not merely skip this snapshot slot.
	admitted := false
	plane.PauseOutboundConnectivityUpdates()
	plane.resumeOutboundConnectivityUpdates(func(_ uint8, alive bool, nt *dialer.NetworkType) {
		if nt.HealthKey() == data.HealthKey() {
			admitted = alive
		}
	})
	if !admitted {
		t.Fatal("resume blocked a data UDP path with a selectable DNS UDP fallback")
	}
}
