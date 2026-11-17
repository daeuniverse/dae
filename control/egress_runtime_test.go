/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"context"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func TestEgressSnapshotsReplaceOldSelections(t *testing.T) {
	option := &dialer.GlobalOption{Log: logrus.New(), CheckInterval: time.Second}
	dialers := []*dialer.Dialer{
		dialer.NewDialerContext(context.Background(), noopAdmissionDialer{}, option, dialer.InstanceOption{DisableCheck: true}, &dialer.Property{Property: D.Property{Name: "first"}}),
		dialer.NewDialerContext(context.Background(), noopAdmissionDialer{}, option, dialer.InstanceOption{DisableCheck: true}, &dialer.Property{Property: D.Property{Name: "second"}}),
	}
	group := outbound.NewDialerGroup(option, "egress-snapshot-test", dialers, []*dialer.Annotation{{}, {}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Select},
		func(bool, *dialer.NetworkType, bool) {})
	runtime := newEgressRuntime(logrus.New(), nil)
	runtime.configureResources([]*outbound.DialerGroup{group}, dialers, nil)
	t.Cleanup(func() { _ = runtime.releaseOwner() })

	for i := range 100 {
		index := i % len(dialers)
		if _, err := group.SetSelectionBoth(index); err != nil {
			t.Fatalf("set selection: %v", err)
		}
		lease, snapshot, ok := runtime.acquireEgress(dialers[index], group)
		if !ok {
			t.Fatal("acquire egress failed")
		}
		if snapshot.SelectionRevision() != group.SelectionRevision() {
			t.Fatalf("snapshot revision = %d, group revision = %d", snapshot.SelectionRevision(), group.SelectionRevision())
		}
		if err := lease.release(); err != nil {
			t.Fatalf("release lease: %v", err)
		}
		if got := len(runtime.snapshots); got > len(dialers) {
			t.Fatalf("snapshots = %d, want at most one per selected dialer", got)
		}
	}
}
