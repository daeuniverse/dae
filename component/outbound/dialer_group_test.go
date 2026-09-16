/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/sirupsen/logrus"
)

const (
	testTcpCheckUrl = "https://connectivitycheck.gstatic.com/generate_204"
	testUdpCheckDns = "https://connectivitycheck.gstatic.com/generate_204"
)

var TestNetworkType = &dialer.NetworkType{
	L4Proto:   consts.L4ProtoStr_TCP,
	IpVersion: consts.IpVersionStr_4,
	IsDns:     false,
}

var TestDnsUdp4NetworkType = &dialer.NetworkType{
	L4Proto:         consts.L4ProtoStr_UDP,
	IpVersion:       consts.IpVersionStr_4,
	IsDns:           true,
	UdpHealthDomain: dialer.UdpHealthDomainDns,
}

var TestDataUdp4NetworkType = &dialer.NetworkType{
	L4Proto:         consts.L4ProtoStr_UDP,
	IpVersion:       consts.IpVersionStr_4,
	UdpHealthDomain: dialer.UdpHealthDomainData,
}

var log = logrus.New()

func init() {
	logger.SetLogger(log, "trace", false, nil)
}

// newDirectDialer builds a fixture dialer. These fixtures are always full-cone:
// the group tests exercise selection and admission on top of a full-cone direct
// dialer, and the full-cone/non-full-cone split is covered by the dialer tests.
func newDirectDialer(option *dialer.GlobalOption) *dialer.Dialer {
	_d, p := dialer.NewDirectDialer(option, true)
	d := dialer.NewDialerContext(context.Background(), _d, option, dialer.InstanceOption{DisableCheck: false}, p)
	return d
}

func newEmptyAnnotations(n int) []*dialer.Annotation {
	annotations := make([]*dialer.Annotation, n)
	for i := range annotations {
		annotations[i] = &dialer.Annotation{}
	}
	return annotations
}

type noopTestDialer struct{}

func (noopTestDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, errors.New("not implemented")
}

func newNoopDialer(option *dialer.GlobalOption) *dialer.Dialer {
	return dialer.NewDialerContext(context.Background(),
		noopTestDialer{},
		option,
		dialer.InstanceOption{DisableCheck: true},
		&dialer.Property{},
	)
}

func dialerSignalLen(t *testing.T, d *dialer.Dialer, field string) int {
	t.Helper()

	v := reflect.ValueOf(d).Elem().FieldByName(field)
	if !v.IsValid() {
		t.Fatalf("field %q not found", field)
	}
	if v.Kind() != reflect.Chan {
		t.Fatalf("field %q kind = %v, want chan", field, v.Kind())
	}
	return v.Len()
}

func newTestGroupForSelection(policy DialerSelectionPolicy) (*DialerGroup, []*dialer.Dialer) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option),
		newDirectDialer(option),
	}
	group := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)), policy, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	return group, dialers
}

// markDialersDead kills dialers through the real collection-state API:
// NotifyLatencyChange is an out-of-order-tolerant informer that revalidates
// membership against the dialer's collection state, so tests must drive real
// state transitions.
func markDialersDead(set *dialer.AliveDialerSet, dialers ...*dialer.Dialer) {
	for _, d := range dialers {
		d.ReportUnavailableForced(set.CheckTyp, errors.New("offline"))
	}
}

func TestDialerGroup_Select_Fixed(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
		CheckDnsTcp:       false,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option),
		newDirectDialer(option),
	}
	fixedIndex := 1
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: fixedIndex,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	for range 10 {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}

	fixedIndex = 0
	g.SetSelectionPolicy(DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: fixedIndex,
	})
	for range 10 {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}
}

func TestDialerGroup_Select_MinLastLatency(t *testing.T) {

	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_MinLastLatency,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	// Test 1000 times.
	for range 1000 {
		var minLatency time.Duration
		jMinLatency := -1
		for j, d := range dialers {
			// Simulate a latency test.
			var (
				latency time.Duration
				alive   bool
			)
			// 20% chance for timeout.
			if fastrand.Intn(5) == 0 {
				// Simulate a timeout test.
				latency = 1000 * time.Millisecond
				alive = false
			} else {
				// Simulate a normal test.
				latency = time.Duration(fastrand.Int63n(int64(1000 * time.Millisecond)))
				alive = true
			}
			d.MustGetLatencies10(TestNetworkType).AppendLatency(latency)
			if !alive {
				// Real failure: flips the collection and removes the dialer
				// from the set (NotifyLatencyChange is state-revalidated).
				d.ReportUnavailableForced(TestNetworkType, errors.New("timeout"))
			} else {
				// Real revival: restores the collection and re-adds the
				// dialer.
				d.MarkAliveForReloadFallback(TestNetworkType)
			}
			if alive && (jMinLatency == -1 || latency < minLatency) {
				jMinLatency = j
				minLatency = latency
			}
		}
		d, _, err := g.Select(TestNetworkType, true)
		if jMinLatency == -1 {
			if !errors.Is(err, ErrNoAliveDialer) {
				t.Fatalf("expected ErrNoAliveDialer, got: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[jMinLatency] {
			// Get index of d.
			indexD := -1
			for j := range dialers {
				if d == dialers[j] {
					indexD = j
					break
				}
			}
			t.Errorf("dialers[%v] expected, but dialers[%v] selected", jMinLatency, indexD)
		}
	}
}

func TestDialerGroup_Select_Random(t *testing.T) {

	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	count := make([]int, len(dialers))
	for range 100 {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
}

func TestDialerGroup_Resuscitate_UDPTriggersDnsUdpAndTcp(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	d := newNoopDialer(option)
	g := &DialerGroup{
		Dialers: []*dialer.Dialer{d},
	}

	g.resuscitate(TestDataUdp4NetworkType)

	if got := dialerSignalLen(t, d, "checkDnsUdpCh"); got != 1 {
		t.Fatalf("DNS-UDP resuscitation signals = %d, want 1", got)
	}
	if got := dialerSignalLen(t, d, "checkTcpCh"); got != 1 {
		t.Fatalf("TCP resuscitation signals = %d, want 1", got)
	}
}

func TestDialerGroup_Resuscitate_TCPTriggersOnlyTcp(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	d := newNoopDialer(option)
	g := &DialerGroup{
		Dialers: []*dialer.Dialer{d},
	}

	g.resuscitate(TestNetworkType)

	if got := dialerSignalLen(t, d, "checkDnsUdpCh"); got != 0 {
		t.Fatalf("DNS-UDP resuscitation signals = %d, want 0", got)
	}
	if got := dialerSignalLen(t, d, "checkTcpCh"); got != 1 {
		t.Fatalf("TCP resuscitation signals = %d, want 1", got)
	}
}

func TestDialerGroup_SetAlive(t *testing.T) {

	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
		newDirectDialer(option),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	zeroTarget := 3
	// Kill through the dialer state API: NotifyLatencyChange is now an
	// out-of-order-tolerant informer that revalidates membership against the
	// dialer's collection state, so tests must drive real state transitions.
	dialers[zeroTarget].ReportUnavailableForced(TestNetworkType, errors.New("offline"))
	count := make([]int, len(dialers))
	for range 100 {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 && i != zeroTarget {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
	if count[zeroTarget] != 0 {
		t.Fail()
	}
}

func TestDialerGroup_SetSelectionPolicy_FixedToRandomCreatesAliveState(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option),
		newDirectDialer(option),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	if got := g.MustGetAliveDialerSet(TestNetworkType); got != nil {
		t.Fatal("fixed policy should not eagerly allocate alive-state sets")
	}

	g.SetSelectionPolicy(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})

	set := g.MustGetAliveDialerSet(TestNetworkType)
	if set == nil {
		t.Fatal("random policy should allocate alive-state sets on demand")
	}
	if got := set.Len(); got != len(dialers) {
		t.Fatalf("alive dialer count = %d, want %d", got, len(dialers))
	}
}

func TestDialerGroup_SetSelectionPolicy_FixedToRandomPreservesAliveState(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option),
		newDirectDialer(option),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	dialers[1].ReportUnavailableForced(TestNetworkType, errors.New("forced dead for policy switch"))

	g.SetSelectionPolicy(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})

	set := g.MustGetAliveDialerSet(TestNetworkType)
	if set == nil {
		t.Fatal("random policy should allocate alive-state sets")
	}
	if got := set.Len(); got != 1 {
		t.Fatalf("alive dialer count = %d, want 1", got)
	}

	selected, _, err := g.Select(TestNetworkType, true)
	if err != nil {
		t.Fatalf("Select() error after preserving alive state: %v", err)
	}
	if selected != dialers[0] {
		t.Fatal("expected selection to skip dialer that was already dead before policy switch")
	}
}

func TestDialerGroup_SetSelectionPolicy_RecomputesMinLatencyOrdering(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option),
		newDirectDialer(option),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	dialers[0].MustGetLatencies10(TestNetworkType).AppendLatency(90 * time.Millisecond)
	dialers[0].MustGetLatencies10(TestNetworkType).AppendLatency(80 * time.Millisecond)
	dialers[1].MustGetLatencies10(TestNetworkType).AppendLatency(50 * time.Millisecond)
	dialers[1].MustGetLatencies10(TestNetworkType).AppendLatency(40 * time.Millisecond)

	set := g.MustGetAliveDialerSet(TestNetworkType)
	set.NotifyLatencyChange(dialers[0], true)
	set.NotifyLatencyChange(dialers[1], true)

	g.SetSelectionPolicy(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_MinAverage10Latencies,
	})

	selected, _, err := g.Select(TestNetworkType, true)
	if err != nil {
		t.Fatalf("Select() error after policy update: %v", err)
	}
	if selected != dialers[1] {
		t.Fatal("expected lower-average-latency dialer after policy recompute")
	}
}

func TestDialerGroup_Select_DataUdpFallsBackToDnsUdp(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})

	markDialersDead(g.MustGetAliveDialerSet(TestDataUdp4NetworkType), dialers...)
	markDialersDead(g.MustGetAliveDialerSet(TestDnsUdp4NetworkType), dialers[0])
	markDialersDead(g.MustGetAliveDialerSet(TestNetworkType), dialers...)

	d, _, err := g.Select(TestDataUdp4NetworkType, true)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if d != dialers[1] {
		t.Fatalf("expected DNS UDP fallback to select dialers[1], got another dialer")
	}
}

func TestDialerGroup_Select_DataUdpFallsBackToTcp(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})

	markDialersDead(g.MustGetAliveDialerSet(TestDataUdp4NetworkType), dialers...)
	markDialersDead(g.MustGetAliveDialerSet(TestDnsUdp4NetworkType), dialers...)
	markDialersDead(g.MustGetAliveDialerSet(TestNetworkType), dialers[1])

	d, _, err := g.Select(TestDataUdp4NetworkType, true)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if d != dialers[0] {
		t.Fatalf("expected TCP fallback to select dialers[0], got another dialer")
	}
}

func TestDialerGroup_Select_DataUdpFixedPolicyDoesNotFallback(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 1,
	})

	d, _, err := g.Select(TestDataUdp4NetworkType, true)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if d != dialers[1] {
		t.Fatalf("expected fixed policy to keep selecting dialers[1], got another dialer")
	}
}

var TestTcp6NetworkType = &dialer.NetworkType{
	L4Proto:   consts.L4ProtoStr_TCP,
	IpVersion: consts.IpVersionStr_6,
	IsDns:     false,
}

// dataUdpCallbackRecorder records group-level alive callbacks for the
// data-UDP domain of one address family.
type dataUdpCallbackRecorder struct {
	events []string // "init", "true", "false"
}

func (r *dataUdpCallbackRecorder) callback(alive bool, networkType *dialer.NetworkType, isInit bool) {
	if networkType.L4Proto != consts.L4ProtoStr_UDP ||
		networkType.EffectiveUdpHealthDomain() != dialer.UdpHealthDomainData {
		return
	}
	switch {
	case isInit:
		r.events = append(r.events, "init")
	case alive:
		r.events = append(r.events, "true")
	default:
		r.events = append(r.events, "false")
	}
}

// events is appended only from the group constructor and test body, both on
// the test goroutine, so no synchronization is needed.

// newDataUdpCallbackGroup builds a min-latency group of two dialers whose
// DNS-UDP collections hold no latency sample unless seedDnsLatency is set.
func newDataUdpCallbackGroup(t *testing.T, rec *dataUdpCallbackRecorder, seedDnsLatency bool) (*DialerGroup, []*dialer.Dialer) {
	t.Helper()
	return newDataUdpGroup(t, rec.callback, seedDnsLatency)
}

func newDataUdpGroup(t *testing.T, callback func(bool, *dialer.NetworkType, bool), seedDnsLatency bool) (*DialerGroup, []*dialer.Dialer) {
	t.Helper()
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{newDirectDialer(option), newDirectDialer(option)}
	if seedDnsLatency {
		// Control case: DNS-UDP probes succeeded at least once, so the
		// data-UDP set borrows a latency and hasLatency becomes true.
		for _, d := range dialers {
			d.MustGetLatencies10(TestDnsUdp4NetworkType).AppendLatency(50 * time.Millisecond)
		}
	}
	g := NewDialerGroup(option, "callback-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		callback)
	return g, dialers
}

// TestDialerGroup_AliveCallbackSerializesRevalidation ensures an older
// availability callback cannot publish after a newer revival has completed
// membership revalidation.
func TestDialerGroup_AliveCallbackSerializesRevalidation(t *testing.T) {
	deadStarted := make(chan struct{})
	releaseDead := make(chan struct{})
	revivalPublished := make(chan struct{})
	var deadOnce sync.Once
	var revivalOnce sync.Once
	var eventsMu sync.Mutex
	var events []bool
	tracking := false

	callback := func(alive bool, networkType *dialer.NetworkType, isInit bool) {
		if !tracking || isInit || networkType == nil || networkType.L4Proto != consts.L4ProtoStr_UDP ||
			networkType.IpVersion != consts.IpVersionStr_4 || networkType.IsDns ||
			networkType.EffectiveUdpHealthDomain() != dialer.UdpHealthDomainData {
			return
		}
		eventsMu.Lock()
		events = append(events, alive)
		eventsMu.Unlock()
		if alive {
			revivalOnce.Do(func() { close(revivalPublished) })
			return
		}
		deadOnce.Do(func() {
			close(deadStarted)
			<-releaseDead
		})
	}

	g, dialers := newDataUdpGroup(t, callback, false)
	tracking = true
	t.Cleanup(func() { _ = g.Close() })
	set := g.MustGetAliveDialerSet(TestDataUdp4NetworkType)
	if set.Len() != 2 {
		t.Fatalf("setup: alive = %d, want 2", set.Len())
	}

	dialers[0].ReportUnavailableForced(TestDataUdp4NetworkType, errors.New("offline"))
	deadDone := make(chan struct{})
	go func() {
		dialers[1].ReportUnavailableForced(TestDataUdp4NetworkType, errors.New("offline"))
		close(deadDone)
	}()
	select {
	case <-deadStarted:
	case <-time.After(time.Second):
		t.Fatal("dead availability callback did not start")
	}

	revivalDone := make(chan struct{})
	go func() {
		dialers[0].ReportAvailableTraffic(TestDataUdp4NetworkType)
		close(revivalDone)
	}()
	select {
	case <-revivalPublished:
		t.Fatal("revival callback published before the older callback completed")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseDead)
	select {
	case <-deadDone:
	case <-time.After(time.Second):
		t.Fatal("dead availability update did not finish")
	}
	select {
	case <-revivalDone:
	case <-time.After(time.Second):
		t.Fatal("revival availability update did not finish")
	}
	select {
	case <-revivalPublished:
	case <-time.After(time.Second):
		t.Fatal("revival callback did not publish")
	}

	eventsMu.Lock()
	got := append([]bool(nil), events...)
	eventsMu.Unlock()
	if !reflect.DeepEqual(got, []bool{false, true}) {
		t.Fatalf("alive callback sequence = %v, want [false true]", got)
	}
}

// TestDialerGroup_DataUdpRevivalCallback_NoDnsLatency pins the callback
// contract for a data-UDP domain whose DNS-UDP probe never succeeded
// (hasLatency stays false): killing the whole domain fires callback(false),
// and a traffic-driven revival must fire callback(true) symmetrically.
// The callback drives the kernel outbound-connectivity map; a missing
// callback(true) leaves the map at 0 so the kernel keeps dropping every new
// data-UDP flow routed to the group.
//
// Expected sequence (both data-UDP families, udp4 and udp6):
//
//	"true","true" - construction: the first dialer enters each family's
//	                alive set via the no-latency branch
//	"init","init" - NewDialerGroup's init loop for udp4 and udp6
//	"false"       - killing the second dialer empties the udp4 domain
//	"true"        - traffic-driven revival of dialers[0]
func TestDialerGroup_DataUdpRevivalCallback_NoDnsLatency(t *testing.T) {
	rec := &dataUdpCallbackRecorder{}
	g, dialers := newDataUdpCallbackGroup(t, rec, false)

	set := g.MustGetAliveDialerSet(TestDataUdp4NetworkType)
	if set.Len() != 2 {
		t.Fatalf("setup: alive = %d, want 2", set.Len())
	}

	// Kill both dialers through the production state API.
	dialers[0].ReportUnavailableForced(TestDataUdp4NetworkType, errors.New("offline"))
	dialers[1].ReportUnavailableForced(TestDataUdp4NetworkType, errors.New("offline"))
	if set.Len() != 0 {
		t.Fatalf("after kill: alive = %d, want 0", set.Len())
	}

	// Revive through the traffic path (markAvailableTraffic -> inform ->
	// NotifyLatencyChange(d, true)) with no DNS-UDP latency available.
	dialers[0].ReportAvailableTraffic(TestDataUdp4NetworkType)
	if set.Len() != 1 {
		t.Fatalf("after revive: alive = %d, want 1", set.Len())
	}

	want := []string{"true", "true", "init", "init", "false", "true"}
	if !reflect.DeepEqual(rec.events, want) {
		t.Fatalf("data-UDP alive events = %v, want exact sequence %v "+
			"(a missing final \"true\" leaves the kernel connectivity map at 0)",
			rec.events, want)
	}
}

// TestDialerGroup_DataUdpRevivalCallback_WithDnsLatency is the control: once
// a DNS-UDP latency exists, the same kill/revive sequence fires the same
// event sequence via the pre-existing has-latency path.
func TestDialerGroup_DataUdpRevivalCallback_WithDnsLatency(t *testing.T) {
	rec := &dataUdpCallbackRecorder{}
	g, dialers := newDataUdpCallbackGroup(t, rec, true)

	if set := g.MustGetAliveDialerSet(TestDataUdp4NetworkType); set.Len() != 2 {
		t.Fatalf("setup: alive = %d, want 2", set.Len())
	}
	dialers[0].ReportUnavailableForced(TestDataUdp4NetworkType, errors.New("offline"))
	dialers[1].ReportUnavailableForced(TestDataUdp4NetworkType, errors.New("offline"))
	dialers[0].ReportAvailableTraffic(TestDataUdp4NetworkType)

	want := []string{"true", "true", "init", "init", "false", "true"}
	if !reflect.DeepEqual(rec.events, want) {
		t.Fatalf("control case: data-UDP alive events = %v, want exact sequence %v",
			rec.events, want)
	}
}

// TestDialerGroup_PublishAliveChangeRevalidatesStaleNotifications pins the
// publication contract: set callbacks fire outside the set lock, so their
// bool can lag behind a concurrent state flip (a death callback paused while
// a revival completes). publishAliveChange must re-derive the value from the
// set's current membership so a stale notification can never regress the
// kernel connectivity map away from the truth, while init publications pass
// through untouched.
func TestDialerGroup_PublishAliveChangeRevalidatesStaleNotifications(t *testing.T) {
	rec := &dataUdpCallbackRecorder{}
	g, dialers := newDataUdpCallbackGroup(t, rec, false)
	set := g.MustGetAliveDialerSet(TestDataUdp4NetworkType)
	if set.Len() != 2 {
		t.Fatalf("setup: alive = %d, want 2", set.Len())
	}
	n0 := len(rec.events)

	// Both dialers alive: a stale "dead" transition (its callback delayed
	// behind a revival that already happened) must publish the current
	// truth, not the historical bool.
	g.publishAliveChange(false, TestDataUdp4NetworkType, false)

	// Real death empties the domain and fires the real "false" event.
	dialers[0].ReportUnavailableForced(TestDataUdp4NetworkType, errors.New("offline"))
	dialers[1].ReportUnavailableForced(TestDataUdp4NetworkType, errors.New("offline"))
	if set.Len() != 0 {
		t.Fatalf("after kill: alive = %d, want 0", set.Len())
	}

	// Domain dead: a stale "alive" transition must be revalidated down to
	// the current truth as well.
	g.publishAliveChange(true, TestDataUdp4NetworkType, false)

	// Init publications are exempt from revalidation by design.
	g.publishAliveChange(true, TestDataUdp4NetworkType, true)

	// Traffic-driven revival still publishes the real "true".
	dialers[0].ReportAvailableTraffic(TestDataUdp4NetworkType)
	if set.Len() != 1 {
		t.Fatalf("after revive: alive = %d, want 1", set.Len())
	}

	want := []string{"true", "false", "false", "init", "true"}
	if !reflect.DeepEqual(rec.events[n0:], want) {
		t.Fatalf("published events after setup = %v, want %v", rec.events[n0:], want)
	}
}

// TestDialerGroup_Select_SingleDialerLenientFallsBackToFixed pins the
// availability floor: for a single-dialer group, the lenient IP-version
// fallback must not behave worse than the strict path. When both address
// families are dead, Select must still return the only dialer (Fixed
// fallback) instead of ErrNoAliveDialer.
func TestDialerGroup_Select_SingleDialerLenientFallsBackToFixed(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{newDirectDialer(option)}
	g := NewDialerGroup(option, "single-node", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	// Kill the only dialer in both address families through the real
	// collection-state API.
	dialers[0].ReportUnavailableForced(TestNetworkType, errors.New("offline"))
	dialers[0].ReportUnavailableForced(TestTcp6NetworkType, errors.New("offline"))

	// Strict path already returns the dialer via the single-dialer fallback.
	dStrict, _, err := g.Select(TestNetworkType, true)
	if err != nil || dStrict != dialers[0] {
		t.Fatalf("strict Select() = (%v, %v), want the only dialer", dStrict, err)
	}

	// Lenient path must not be worse: after both families fail, it must
	// reach the same single-dialer fallback instead of erroring out.
	dLenient, _, err := g.Select(TestNetworkType, false)
	if err != nil {
		t.Fatalf("lenient Select() error = %v, want single-dialer fallback", err)
	}
	if dLenient != dialers[0] {
		t.Fatalf("lenient Select() returned %v, want the only dialer", dLenient)
	}
}

// TestPublishAliveChangeWithoutAliveSetIsPolicyDriven is a regression guard:
// when the network type has no AliveDialerSet, publishAliveChange used to trust
// the incoming bool, which could write 0 into the kernel outbound-connectivity
// slot for a group that is usable (Fixed groups have no set at all and no probe
// that would ever repair the slot).
func TestPublishAliveChangeWithoutAliveSetIsPolicyDriven(t *testing.T) {
	type call struct {
		alive bool
		init  bool
	}
	newGroup := func(policy consts.DialerSelectionPolicy) (*DialerGroup, *[]call) {
		var calls []call
		g := &DialerGroup{
			log:  log,
			Name: "test-group",
			aliveChangeCallback: func(alive bool, _ *dialer.NetworkType, isInit bool) {
				calls = append(calls, call{alive: alive, init: isInit})
			},
		}
		g.selectionState.Store(&dialerGroupSelectionState{
			policy: DialerSelectionPolicy{Policy: policy},
		})
		return g, &calls
	}
	nt := TestDataUdp4NetworkType

	t.Run("fixed publishes alive", func(t *testing.T) {
		g, calls := newGroup(consts.DialerSelectionPolicy_Fixed)
		g.publishAliveChange(false, nt, false)
		if len(*calls) != 1 || !(*calls)[0].alive {
			t.Fatalf("Fixed group with no alive set must publish alive=true, got %+v", *calls)
		}
		if got := g.alivePublishMissingSetCount.Load(); got != 0 {
			t.Fatalf("Fixed must not be counted as a missing-set defect: %d", got)
		}
	})

	t.Run("random publishes alive", func(t *testing.T) {
		g, calls := newGroup(consts.DialerSelectionPolicy_Random)
		g.publishAliveChange(false, nt, false)
		if len(*calls) != 1 || !(*calls)[0].alive {
			t.Fatalf("Random group with no alive set must publish alive=true, got %+v", *calls)
		}
	})

	t.Run("min policy keeps last value and counts", func(t *testing.T) {
		g, calls := newGroup(consts.DialerSelectionPolicy_MinLastLatency)
		g.publishAliveChange(false, nt, false)
		if len(*calls) != 0 {
			t.Fatalf("a missing set for a policy that needs alive state must not publish, got %+v", *calls)
		}
		if got := g.alivePublishMissingSetCount.Load(); got != 1 {
			t.Fatalf("missing-set occurrences = %d, want 1", got)
		}
		// Init publications stay trusted: a fresh group publishes optimistic
		// aliveness before its health converges.
		g.publishAliveChange(true, nt, true)
		if len(*calls) != 1 || !(*calls)[0].alive || !(*calls)[0].init {
			t.Fatalf("init publication must be passed through, got %+v", *calls)
		}
	})
}

// TestGroupPublishesOptimisticAlive pins the policy set whose kernel admission
// stays open regardless of per-dialer health.
func TestGroupPublishesOptimisticAlive(t *testing.T) {
	for _, tc := range []struct {
		policy consts.DialerSelectionPolicy
		want   bool
	}{
		{consts.DialerSelectionPolicy_Fixed, true},
		{consts.DialerSelectionPolicy_Random, true},
		{consts.DialerSelectionPolicy_MinLastLatency, false},
		{consts.DialerSelectionPolicy_MinAverage10Latencies, false},
		{consts.DialerSelectionPolicy_MinMovingAverageLatencies, false},
	} {
		if got := groupPublishesOptimisticAlive(tc.policy); got != tc.want {
			t.Fatalf("groupPublishesOptimisticAlive(%v) = %v, want %v", tc.policy, got, tc.want)
		}
	}
}
