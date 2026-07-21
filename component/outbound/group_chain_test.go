/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type groupChainTestExit struct {
	mu    sync.Mutex
	fail  bool
	calls int
}

func (d *groupChainTestExit) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	d.mu.Lock()
	d.calls++
	fail := d.fail
	d.mu.Unlock()
	if fail {
		return nil, errors.New("unreachable")
	}
	left, right := net.Pipe()
	_ = right.Close()
	return left, nil
}

func (d *groupChainTestExit) setFail(fail bool) {
	d.mu.Lock()
	d.fail = fail
	d.mu.Unlock()
}

func (d *groupChainTestExit) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func newGroupChainTestEntry(option *dialer.GlobalOption, name string) *dialer.Dialer {
	return dialer.NewDialer(noopTestDialer{}, option, dialer.InstanceOption{DisableCheck: true}, &dialer.Property{
		Property: D.Property{Name: name, Link: name + ": direct://"},
	})
}

func setGroupChainTestHealth(d *dialer.Dialer, latency time.Duration) {
	snapshot := d.HealthSnapshot()
	for _, idx := range []int{dialer.IdxTcp4, dialer.IdxDnsTcp4} {
		snapshot.Collections[idx].Alive = true
		snapshot.Collections[idx].Latencies = dialer.LatenciesNSnapshot{
			Latencies:     []time.Duration{latency},
			SumNLatencies: latency,
		}
	}
	d.RestoreHealthSnapshot(snapshot)
}

func newGroupChainTestGroup(policy DialerSelectionPolicy) (*DialerGroup, []*dialer.Dialer) {
	option := &dialer.GlobalOption{Log: log, CheckInterval: 10 * time.Second}
	entries := []*dialer.Dialer{
		newGroupChainTestEntry(option, "HK1"),
		newGroupChainTestEntry(option, "HK2"),
	}
	group := NewDialerGroup(option, "HK", entries, newEmptyAnnotations(len(entries)), policy, func(bool, *dialer.NetworkType, bool) {})
	setGroupChainTestHealth(entries[0], time.Millisecond)
	setGroupChainTestHealth(entries[1], 2*time.Millisecond)
	return group, entries
}

func TestGroupChainFailoverAndRecovery(t *testing.T) {
	group, entries := newGroupChainTestGroup(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency})
	hk1 := &groupChainTestExit{fail: true}
	hk2 := &groupChainTestExit{}
	chain := &groupChainDialer{
		entry:  group,
		spec:   common.GroupChain{EntryGroup: "HK", ExitLink: "vmess://exit"},
		exits:  map[*dialer.Dialer]netproxy.Dialer{entries[0]: hk1, entries[1]: hk2},
		option: &dialer.GlobalOption{Log: log},
	}

	conn, err := chain.DialContext(context.Background(), "tcp4", "1.1.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if hk1.callCount() != 1 || hk2.callCount() != 1 {
		t.Fatalf("calls after failover = HK1:%d HK2:%d, want 1/1", hk1.callCount(), hk2.callCount())
	}

	hk1.setFail(false)
	chain.mu.Lock()
	chain.retryAt[dialer.IdxTcp4] = map[*dialer.Dialer]time.Time{entries[0]: time.Now().Add(-time.Second)}
	chain.mu.Unlock()
	conn, err = chain.DialContext(context.Background(), "tcp4", "1.1.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if hk1.callCount() != 2 {
		t.Fatalf("HK1 calls after recovery = %d, want 2", hk1.callCount())
	}
}

func TestGroupChainFixedDoesNotFailOver(t *testing.T) {
	group, entries := newGroupChainTestGroup(DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0})
	hk1 := &groupChainTestExit{fail: true}
	hk2 := &groupChainTestExit{}
	chain := &groupChainDialer{
		entry: group,
		spec:  common.GroupChain{EntryGroup: "HK"},
		exits: map[*dialer.Dialer]netproxy.Dialer{entries[0]: hk1, entries[1]: hk2},
	}

	_, err := chain.DialContext(context.Background(), "tcp4", "1.1.1.1:443")
	if err == nil {
		t.Fatal("expected fixed chain failure")
	}
	if hk1.callCount() != 1 || hk2.callCount() != 0 {
		t.Fatalf("calls = HK1:%d HK2:%d, want 1/0", hk1.callCount(), hk2.callCount())
	}
}

func TestGroupChainReportsUnavailableEntry(t *testing.T) {
	option := &dialer.GlobalOption{Log: log, CheckInterval: 10 * time.Second}
	group := NewDialerGroup(option, "HK", nil, nil,
		DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	chain := &groupChainDialer{
		entry: group,
		spec:  common.GroupChain{EntryGroup: "HK"},
		exits: map[*dialer.Dialer]netproxy.Dialer{},
	}

	_, err := chain.DialContext(context.Background(), "tcp4", "1.1.1.1:443")
	if err == nil || !strings.Contains(err.Error(), "entry node unavailable") {
		t.Fatalf("err = %v, want entry node unavailable", err)
	}
}

func TestRestoreGroupChainSelectionByEntryName(t *testing.T) {
	option := &dialer.GlobalOption{Log: log, CheckInterval: 10 * time.Second}
	oldEntry := newGroupChainTestEntry(option, "HK2")
	newEntry := newGroupChainTestEntry(option, "HK2")
	policy := DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}
	oldGroup := NewDialerGroup(option, "HK", []*dialer.Dialer{oldEntry}, newEmptyAnnotations(1), policy, func(bool, *dialer.NetworkType, bool) {})
	newGroup := NewDialerGroup(option, "HK", []*dialer.Dialer{newEntry}, newEmptyAnnotations(1), policy, func(bool, *dialer.NetworkType, bool) {})
	oldChain := &groupChainDialer{
		entry:   oldGroup,
		spec:    common.GroupChain{EntryGroup: "HK", ExitLink: "vmess://exit"},
		exits:   map[*dialer.Dialer]netproxy.Dialer{oldEntry: &groupChainTestExit{}},
		current: [8]*dialer.Dialer{dialer.IdxTcp4: oldEntry},
		retryAt: [8]map[*dialer.Dialer]time.Time{dialer.IdxTcp4: {oldEntry: time.Now().Add(time.Hour)}},
	}
	newChain := &groupChainDialer{
		entry: newGroup,
		spec:  common.GroupChain{EntryGroup: "HK", ExitLink: "vmess://exit"},
		exits: map[*dialer.Dialer]netproxy.Dialer{newEntry: &groupChainTestExit{}},
	}

	RestoreGroupChainSelection(newChain, oldChain)
	if newChain.current[dialer.IdxTcp4] != newEntry || !newChain.preferCurrent[dialer.IdxTcp4] {
		t.Fatal("stable entry selection was not restored")
	}
	if newChain.retryAt[dialer.IdxTcp4] != nil {
		t.Fatal("transient retry state must not be restored")
	}
}

func TestGroupChainNetworkTypeKeepsHealthDomainsSeparate(t *testing.T) {
	udp6 := netproxy.MagicNetwork{Network: "udp", IPVersion: "6"}.Encode()
	got := groupChainNetworkType(udp6, "1.1.1.1:53")
	if got.L4Proto != consts.L4ProtoStr_UDP || got.IpVersion != consts.IpVersionStr_6 ||
		got.EffectiveUdpHealthDomain() != dialer.UdpHealthDomainDns {
		t.Fatalf("UDP type = %#v", got)
	}
	tcp4 := groupChainNetworkType("tcp4", "1.1.1.1:443")
	if tcp4.L4Proto != consts.L4ProtoStr_TCP || tcp4.IpVersion != consts.IpVersionStr_4 {
		t.Fatalf("TCP type = %#v", tcp4)
	}
}
