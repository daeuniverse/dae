package cmd

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

type shutdownCallRecorder struct {
	order []string
}

func (r *shutdownCallRecorder) add(call string) {
	r.order = append(r.order, call)
}

type fakeShutdownListener struct {
	recorder *shutdownCallRecorder
}

func (f *fakeShutdownListener) Close() error {
	if f.recorder != nil {
		f.recorder.add("listener.Close")
	}
	return nil
}

type fakeShutdownControlPlane struct {
	recorder    *shutdownCallRecorder
	detachCalls int
	abortCalls  int
	closeCalls  int
	detachErr   error
	abortErr    error
	closeErr    error
	onClose     func()
}

func (f *fakeShutdownControlPlane) DetachBpfHooks() error {
	f.detachCalls++
	if f.recorder != nil {
		f.recorder.add("control.DetachBpfHooks")
	}
	return f.detachErr
}

func (f *fakeShutdownControlPlane) AbortConnections() error {
	f.abortCalls++
	if f.recorder != nil {
		f.recorder.add("control.AbortConnections")
	}
	return f.abortErr
}

func (f *fakeShutdownControlPlane) Close() error {
	f.closeCalls++
	if f.recorder != nil {
		f.recorder.add("control.Close")
	}
	if f.onClose != nil {
		f.onClose()
	}
	return f.closeErr
}

type fakeShutdownNetns struct {
	recorder   *shutdownCallRecorder
	closeCalls int
	closeErr   error
}

func (f *fakeShutdownNetns) Close() error {
	f.closeCalls++
	if f.recorder != nil {
		f.recorder.add("netns.Close")
	}
	return f.closeErr
}

type fakeRetirementControlPlane struct {
	active int32
	idleCh chan struct{}
}

func newFakeRetirementControlPlane(active int32) *fakeRetirementControlPlane {
	f := &fakeRetirementControlPlane{
		active: active,
		idleCh: make(chan struct{}),
	}
	if active == 0 {
		close(f.idleCh)
	}
	return f
}

func (f *fakeRetirementControlPlane) ActiveSessionCount() int {
	return int(atomic.LoadInt32(&f.active))
}

func (f *fakeRetirementControlPlane) DrainIdleCh() <-chan struct{} {
	return f.idleCh
}

func newDiscardLogger() *logrus.Logger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

func isolateGlobalUdpState(t *testing.T) {
	t.Helper()

	oldEndpointPool := control.DefaultUdpEndpointPool
	oldAnyfromPool := control.DefaultAnyfromPool
	oldTaskPool := control.DefaultUdpTaskPool
	oldSnifferPool := control.DefaultPacketSnifferSessionMgr

	endpointPool := control.NewUdpEndpointPool()
	anyfromPool := control.NewAnyfromPool()
	taskPool := control.NewUdpTaskPool()
	snifferPool := control.NewPacketSnifferPool()

	control.DefaultUdpEndpointPool = endpointPool
	control.DefaultAnyfromPool = anyfromPool
	control.DefaultUdpTaskPool = taskPool
	control.DefaultPacketSnifferSessionMgr = snifferPool

	t.Cleanup(func() {
		endpointPool.Close()
		anyfromPool.Close()
		taskPool.Close()
		snifferPool.Close()

		control.DefaultUdpEndpointPool = oldEndpointPool
		control.DefaultAnyfromPool = oldAnyfromPool
		control.DefaultUdpTaskPool = oldTaskPool
		control.DefaultPacketSnifferSessionMgr = oldSnifferPool
	})
}

func seedPacketSnifferSession(t *testing.T) control.PacketSnifferKey {
	t.Helper()

	key := control.NewPacketSnifferKey(
		netip.MustParseAddrPort("192.0.2.10:40000"),
		netip.MustParseAddrPort("198.51.100.20:443"),
		[]byte{0x01, 0x02, 0x03},
	)
	if _, isNew := control.DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil); !isNew {
		t.Fatal("expected test packet sniffer session to be newly created")
	}
	if got := control.DefaultPacketSnifferSessionMgr.Get(key); got == nil {
		t.Fatal("expected seeded packet sniffer session to be present")
	}
	return key
}

func TestShutdownAfterSignalFastExitSkipsGracefulTeardown(t *testing.T) {
	recorder := &shutdownCallRecorder{}
	listener := &fakeShutdownListener{recorder: recorder}
	plane := &fakeShutdownControlPlane{recorder: recorder}
	netns := &fakeShutdownNetns{recorder: recorder}

	if err := shutdownAfterSignal(newDiscardLogger(), listener, plane, netns, true); err != nil {
		t.Fatalf("shutdownAfterSignal() error = %v", err)
	}

	if plane.detachCalls != 1 {
		t.Fatalf("DetachBpfHooks calls = %d, want 1", plane.detachCalls)
	}
	if plane.abortCalls != 0 {
		t.Fatalf("AbortConnections calls = %d, want 0", plane.abortCalls)
	}
	if plane.closeCalls != 0 {
		t.Fatalf("Close calls = %d, want 0", plane.closeCalls)
	}
	if netns.closeCalls != 0 {
		t.Fatalf("netns.Close calls = %d, want 0", netns.closeCalls)
	}

	wantOrder := []string{
		"listener.Close",
		"control.DetachBpfHooks",
	}
	if !reflect.DeepEqual(recorder.order, wantOrder) {
		t.Fatalf("call order = %v, want %v", recorder.order, wantOrder)
	}
}

func TestShutdownAfterSignalGracefulExitRunsFullTeardown(t *testing.T) {
	isolateGlobalUdpState(t)

	recorder := &shutdownCallRecorder{}
	listener := &fakeShutdownListener{recorder: recorder}
	plane := &fakeShutdownControlPlane{
		recorder: recorder,
		closeErr: errors.New("close failed"),
	}
	netns := &fakeShutdownNetns{recorder: recorder}

	err := shutdownAfterSignal(newDiscardLogger(), listener, plane, netns, false)
	if err == nil || err.Error() != "close control plane: close failed" {
		t.Fatalf("shutdownAfterSignal() error = %v, want close control plane: close failed", err)
	}

	if plane.detachCalls != 1 {
		t.Fatalf("DetachBpfHooks calls = %d, want 1", plane.detachCalls)
	}
	if plane.abortCalls != 1 {
		t.Fatalf("AbortConnections calls = %d, want 1", plane.abortCalls)
	}
	if plane.closeCalls != 1 {
		t.Fatalf("Close calls = %d, want 1", plane.closeCalls)
	}
	if netns.closeCalls != 1 {
		t.Fatalf("netns.Close calls = %d, want 1", netns.closeCalls)
	}

	wantOrder := []string{
		"listener.Close",
		"control.DetachBpfHooks",
		"netns.Close",
		"control.AbortConnections",
		"control.Close",
	}
	if !reflect.DeepEqual(recorder.order, wantOrder) {
		t.Fatalf("call order = %v, want %v", recorder.order, wantOrder)
	}
}

func TestShutdownAfterSignalGracefulExitResetsGlobalUdpStateAfterClose(t *testing.T) {
	isolateGlobalUdpState(t)

	key := seedPacketSnifferSession(t)
	plane := &fakeShutdownControlPlane{
		onClose: func() {
			if got := control.DefaultPacketSnifferSessionMgr.Get(key); got == nil {
				t.Fatal("global UDP state was reset before control plane close")
			}
		},
	}

	if err := shutdownAfterSignal(newDiscardLogger(), &fakeShutdownListener{}, plane, &fakeShutdownNetns{}, false); err != nil {
		t.Fatalf("shutdownAfterSignal() error = %v", err)
	}

	if plane.closeCalls != 1 {
		t.Fatalf("Close calls = %d, want 1", plane.closeCalls)
	}
	if got := control.DefaultPacketSnifferSessionMgr.Get(key); got != nil {
		t.Fatal("expected graceful shutdown to reset global UDP packet sniffer state")
	}
}

func TestShutdownAfterSignalFastExitDoesNotResetGlobalUdpState(t *testing.T) {
	isolateGlobalUdpState(t)

	key := seedPacketSnifferSession(t)

	if err := shutdownAfterSignal(newDiscardLogger(), &fakeShutdownListener{}, &fakeShutdownControlPlane{}, &fakeShutdownNetns{}, true); err != nil {
		t.Fatalf("shutdownAfterSignal() error = %v", err)
	}

	if got := control.DefaultPacketSnifferSessionMgr.Get(key); got == nil {
		t.Fatal("expected fast shutdown to leave global UDP packet sniffer state intact")
	}
}

func TestShutdownAfterSignalTypedNilResourcesAreSkipped(t *testing.T) {
	var listener *control.Listener
	var plane *control.ControlPlane
	var netns *control.DaeNetns

	if err := shutdownAfterSignal(newDiscardLogger(), listener, plane, netns, true); err != nil {
		t.Fatalf("shutdownAfterSignal() error = %v, want nil", err)
	}
}

func TestShutdownAfterSignalWithPendingHandoffFastExitDetachesBothGenerations(t *testing.T) {
	recorder := &shutdownCallRecorder{}
	newListener := &fakeShutdownListener{recorder: recorder}
	oldListener := &fakeShutdownListener{recorder: recorder}
	newPlane := &fakeShutdownControlPlane{recorder: recorder}
	oldPlane := &fakeShutdownControlPlane{recorder: recorder}
	netns := &fakeShutdownNetns{recorder: recorder}

	err := shutdownAfterSignalWithHandoff(
		newDiscardLogger(),
		newListener,
		newPlane,
		netns,
		true,
		&signalShutdownStagedHandoff{
			oldListener:     oldListener,
			oldControlPlane: oldPlane,
			newListener:     newListener,
			newControlPlane: newPlane,
		},
	)
	if err != nil {
		t.Fatalf("shutdownAfterSignalWithHandoff() error = %v", err)
	}

	if newPlane.detachCalls != 1 {
		t.Fatalf("newPlane DetachBpfHooks calls = %d, want 1", newPlane.detachCalls)
	}
	if oldPlane.detachCalls != 1 {
		t.Fatalf("oldPlane DetachBpfHooks calls = %d, want 1", oldPlane.detachCalls)
	}
	if newPlane.abortCalls != 0 || oldPlane.abortCalls != 0 {
		t.Fatalf("AbortConnections calls = (%d, %d), want (0, 0)", newPlane.abortCalls, oldPlane.abortCalls)
	}
	if newPlane.closeCalls != 0 || oldPlane.closeCalls != 0 {
		t.Fatalf("Close calls = (%d, %d), want (0, 0)", newPlane.closeCalls, oldPlane.closeCalls)
	}
	if netns.closeCalls != 0 {
		t.Fatalf("netns.Close calls = %d, want 0", netns.closeCalls)
	}

	wantOrder := []string{
		"listener.Close",
		"listener.Close",
		"control.DetachBpfHooks",
		"control.DetachBpfHooks",
	}
	if !reflect.DeepEqual(recorder.order, wantOrder) {
		t.Fatalf("call order = %v, want %v", recorder.order, wantOrder)
	}
}

func TestNotifyRunStateChangeCoalescesPendingNotification(t *testing.T) {
	runStateChanges := make(chan struct{}, 1)

	notifyRunStateChange(runStateChanges)
	notifyRunStateChange(runStateChanges)

	select {
	case <-runStateChanges:
	default:
		t.Fatal("expected a pending run-state notification")
	}

	select {
	case <-runStateChanges:
		t.Fatal("expected notifications to coalesce while the channel is full")
	default:
	}
}

func TestTryQueueReloadRequestRejectsConcurrentReload(t *testing.T) {
	reqs := make(chan reloadRequest, 1)
	var reloadActive atomic.Bool
	var reloadPending atomic.Bool

	if !tryQueueReloadRequest(newDiscardLogger(), reqs, &reloadActive, &reloadPending, reloadRequest{isSuspend: false}) {
		t.Fatal("expected first reload request to be queued")
	}
	if !reloadPending.Load() {
		t.Fatal("expected reloadPending to remain set after queuing reload")
	}
	if tryQueueReloadRequest(newDiscardLogger(), reqs, &reloadActive, &reloadPending, reloadRequest{isSuspend: true}) {
		t.Fatal("expected concurrent reload request to be rejected")
	}

	select {
	case req := <-reqs:
		if req.isSuspend {
			t.Fatal("expected first queued reload request to be preserved")
		}
	default:
		t.Fatal("expected queued reload request")
	}
}

func TestRestoreRejectedReloadProgressUsesBusyWhileSettling(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	oldWriter := setRunSignalProgress
	oldReader := getRunSignalProgress
	setRunSignalProgress = func(code byte, content string) error {
		return writeSignalProgressFile(progressPath, code, content)
	}
	getRunSignalProgress = func() (byte, string, error) {
		return readSignalProgressFile(progressPath)
	}
	t.Cleanup(func() {
		setRunSignalProgress = oldWriter
		getRunSignalProgress = oldReader
	})

	restoreRejectedReloadProgress(nil, false)

	code, content, err := readSignalProgressFile(progressPath)
	if err != nil {
		t.Fatalf("readSignalProgressFile() error = %v", err)
	}
	if code != consts.ReloadBusy {
		t.Fatalf("code = %q, want ReloadBusy", code)
	}
	if content == "" {
		t.Fatal("expected settling rejection to write a human-readable message")
	}
}

func TestRestoreRejectedReloadProgressUsesBusyWhileActive(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	oldWriter := setRunSignalProgress
	oldReader := getRunSignalProgress
	setRunSignalProgress = func(code byte, content string) error {
		return writeSignalProgressFile(progressPath, code, content)
	}
	getRunSignalProgress = func() (byte, string, error) {
		return readSignalProgressFile(progressPath)
	}
	t.Cleanup(func() {
		setRunSignalProgress = oldWriter
		getRunSignalProgress = oldReader
	})

	var reloadActive atomic.Bool
	reloadActive.Store(true)

	restoreRejectedReloadProgress(&reloadActive, false)

	code, content, err := readSignalProgressFile(progressPath)
	if err != nil {
		t.Fatalf("readSignalProgressFile() error = %v", err)
	}
	if code != consts.ReloadBusy {
		t.Fatalf("code = %q, want ReloadBusy", code)
	}
	if content == "" {
		t.Fatal("expected active rejection to write a human-readable message")
	}
}

func TestReleaseReloadPendingAfterRetirementWaitsForCompletion(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	oldWriter := setRunSignalProgress
	oldReader := getRunSignalProgress
	setRunSignalProgress = func(code byte, content string) error {
		return writeSignalProgressFile(progressPath, code, content)
	}
	getRunSignalProgress = func() (byte, string, error) {
		return readSignalProgressFile(progressPath)
	}
	t.Cleanup(func() {
		setRunSignalProgress = oldWriter
		getRunSignalProgress = oldReader
	})

	if err := writeSignalProgressFile(progressPath, consts.ReloadBusy, reloadBusyRetiringMessage); err != nil {
		t.Fatalf("writeSignalProgressFile() error = %v", err)
	}

	var reloadPending atomic.Bool
	reloadPending.Store(true)
	retirementDone := make(chan struct{})

	releaseReloadPendingAfterRetirement(&reloadPending, retirementDone)
	if !reloadPending.Load() {
		t.Fatal("expected reloadPending to remain set before retirement completes")
	}
	close(retirementDone)
	deadline := time.After(time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !reloadPending.Load() {
			code, content, err := readSignalProgressFile(progressPath)
			if err != nil {
				t.Fatalf("readSignalProgressFile() error = %v", err)
			}
			if code == consts.ReloadDone && content == "" {
				break
			}
		}
		select {
		case <-deadline:
			t.Fatal("expected reloadPending and progress file to settle after retirement completes")
		case <-ticker.C:
		}
	}
}

func TestRemainingReloadRetirementBudgetUsesElapsedTime(t *testing.T) {
	budget := 10 * time.Second
	remaining := remainingReloadRetirementBudget(time.Now().Add(-3*time.Second), budget)
	if remaining <= 0 {
		t.Fatal("expected positive remaining budget")
	}
	if remaining >= budget {
		t.Fatal("expected elapsed time to reduce remaining budget")
	}
}

func TestRemainingReloadRetirementBudgetClampsAtZero(t *testing.T) {
	if remaining := remainingReloadRetirementBudget(time.Now().Add(-15*time.Second), 10*time.Second); remaining != 0 {
		t.Fatalf("remaining = %v, want 0", remaining)
	}
}

func TestBeginReloadHandoffSetsReloadingBeforeNotification(t *testing.T) {
	var reloading atomic.Bool
	runStateChanges := make(chan struct{}, 1)

	beginReloadHandoff(&reloading, runStateChanges)

	select {
	case <-runStateChanges:
	default:
		t.Fatal("expected a pending run-state notification")
	}

	if !reloading.Load() {
		t.Fatal("expected reload handoff to remain latched until the consumer clears it")
	}
}

func TestReloadManagerBuildShutdownHandoffUsesPendingStagedHandoff(t *testing.T) {
	oldListener := &control.Listener{}
	newListener := &control.Listener{}
	oldPlane := &control.ControlPlane{}
	newPlane := &control.ControlPlane{}

	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	manager.setPendingStagedHandoff(&stagedReloadHandoff{
		oldControlPlane: oldPlane,
		oldListener:     oldListener,
		newControlPlane: newPlane,
		newListener:     newListener,
	}, time.Now(), 123)

	handoff := manager.buildShutdownHandoff()
	if handoff == nil {
		t.Fatal("buildShutdownHandoff() = nil, want non-nil handoff")
	}
	if handoff.oldControlPlane != oldPlane || handoff.newControlPlane != newPlane {
		t.Fatal("expected shutdown handoff to preserve control plane ownership")
	}
	if handoff.oldListener != oldListener || handoff.newListener != newListener {
		t.Fatal("expected shutdown handoff to preserve listener ownership")
	}
}

func TestReloadManagerCoalesceReloadRequestKeepsLatestQueuedRequest(t *testing.T) {
	reloadReqs := make(chan reloadRequest, 2)
	manager := newReloadManager(reloadReqs, make(chan struct{}, 1), make(chan os.Signal, 1))

	now := time.Now()
	latest := reloadRequest{
		isSuspend:       true,
		requestedAt:     now.Add(time.Second),
		requestedAtMono: 99,
	}
	reloadReqs <- latest

	got := manager.coalesceReloadRequest(reloadRequest{
		isSuspend:       false,
		requestedAt:     now,
		requestedAtMono: 11,
	})

	if got != latest {
		t.Fatalf("coalesceReloadRequest() = %+v, want latest queued %+v", got, latest)
	}
}

func TestDNSConfigEqualUsesStableFingerprint(t *testing.T) {
	oldConf := &config.Config{
		Dns: config.Dns{
			Bind:               "127.0.0.1:53",
			IpVersionPrefer:    4,
			Upstream:           []config.KeyableString{"google:udp://8.8.8.8:53"},
			OptimisticCache:    true,
			OptimisticCacheTtl: 60,
		},
	}
	newConf := &config.Config{Dns: oldConf.Dns}
	if !dnsConfigEqual(oldConf, newConf) {
		t.Fatal("expected identical DNS configs to compare equal")
	}

	newConf.Dns.Bind = "127.0.0.1:5353"
	if dnsConfigEqual(oldConf, newConf) {
		t.Fatal("expected changed DNS config to compare unequal")
	}
}

func TestDNSConfigFingerprintCoversAllDnsFields(t *testing.T) {
	// Fields that MUST be covered by dnsConfigFingerprint because they
	// affect BPF datapath state (domain_routing_map, routing rules, upstream).
	covered := map[string]struct{}{
		"IpVersionPrefer": {},
		"FixedDomainTtl":  {},
		"Upstream":        {},
		"Routing":         {},
		"Bind":            {},
	}

	// Fields that are intentionally EXCLUDED from dnsConfigFingerprint
	// because they are runtime-tunable via DnsController.UpdateRuntime
	// (atomic stores) and do not affect BPF map state. Including them
	// would cause unnecessary domain_routing_map clear+replay during
	// staged handoff (dae#1013).
	excluded := map[string]struct{}{
		"OptimisticCache":    {},
		"OptimisticCacheTtl": {},
		"MaxCacheSize":       {},
	}

	dnsType := reflect.TypeOf(config.Dns{})
	for i := 0; i < dnsType.NumField(); i++ {
		name := dnsType.Field(i).Name
		if _, isExcluded := excluded[name]; isExcluded {
			continue
		}
		if _, ok := covered[name]; !ok {
			t.Fatalf("dnsConfigFingerprint does not cover config.Dns.%s", name)
		}
		delete(covered, name)
	}
	for name := range covered {
		t.Fatalf("dnsConfigFingerprint coverage references missing config.Dns.%s", name)
	}
}

// --- bpfDatapathChanged tests ---

func baseConfig() *config.Config {
	return &config.Config{
		Global: config.Global{
			LanInterface:        []string{"eth0"},
			WanInterface:        []string{"eth1"},
			BpfConnStateMapSize: 262144,
			SoMarkFromDae:       0x80,
			SoMarkFromDaeSet:    true,
		},
		Group: []config.Group{
			{Name: "proxy", Policy: config.FunctionListOrString("min_avg")},
		},
		Routing: config.Routing{
			Rules:    []*config_parser.RoutingRule{},
			Fallback: config.FunctionOrString("direct"),
		},
		Dns: config.Dns{
			IpVersionPrefer: 4,
			Upstream:        []config.KeyableString{"1.1.1.1"},
			Bind:            "127.0.0.1:53",
			Routing: config.DnsRouting{
				Request: config.DnsRequestRouting{
					Fallback: config.FunctionOrString("proxy"),
				},
				Response: config.DnsResponseRouting{
					Fallback: config.FunctionOrString("proxy"),
				},
			},
		},
	}
}

func TestBpfDatapathChanged_IdenticalConfigs(t *testing.T) {
	old := baseConfig()
	new := baseConfig()
	if bpfDatapathChanged(old, new) {
		t.Fatal("expected identical configs to not trigger datapath change")
	}
}

func TestBpfDatapathChanged_NilConfigs(t *testing.T) {
	if !bpfDatapathChanged(nil, baseConfig()) {
		t.Fatal("expected nil old config to trigger datapath change")
	}
	if !bpfDatapathChanged(baseConfig(), nil) {
		t.Fatal("expected nil new config to trigger datapath change")
	}
}

func TestBpfDatapathChanged_SafeFieldsOnly(t *testing.T) {
	old := baseConfig()
	new := baseConfig()
	// These are all pure userspace fields that do not affect BPF maps.
	new.Global.LogLevel = "debug"
	new.Global.TcpCheckUrl = []string{"http://example.com"}
	new.Global.DialMode = "domain++"
	new.Global.SniffingTimeout = 50 * time.Millisecond
	new.Global.AllowInsecure = true
	new.Global.Mptcp = true
	new.Global.PprofPort = 6060
	new.Global.BandwidthMaxTx = "100M"
	// DNS runtime params (excluded by fingerprint).
	new.Dns.OptimisticCache = false
	new.Dns.OptimisticCacheTtl = 120
	new.Dns.MaxCacheSize = 5000
	if bpfDatapathChanged(old, new) {
		t.Fatal("expected safe-only field changes to NOT trigger datapath change")
	}
}

func TestBpfDatapathChanged_RoutingRules(t *testing.T) {
	old := baseConfig()
	new := baseConfig()
	new.Routing.Rules = []*config_parser.RoutingRule{
		{Outbound: config_parser.Function{Name: "direct"}},
	}
	if !bpfDatapathChanged(old, new) {
		t.Fatal("expected routing rule change to trigger datapath change")
	}
}

func TestBpfDatapathChanged_RoutingFallback(t *testing.T) {
	old := baseConfig()
	new := baseConfig()
	new.Routing.Fallback = config.FunctionOrString("proxy")
	if !bpfDatapathChanged(old, new) {
		t.Fatal("expected routing fallback change to trigger datapath change")
	}
}

func TestBpfDatapathChanged_Groups(t *testing.T) {
	old := baseConfig()
	new := baseConfig()
	new.Group = append(new.Group, config.Group{
		Name:   "extra",
		Policy: config.FunctionListOrString("min"),
	})
	if !bpfDatapathChanged(old, new) {
		t.Fatal("expected group definition change to trigger datapath change")
	}
}

func TestBpfDatapathChanged_LanInterface(t *testing.T) {
	old := baseConfig()
	new := baseConfig()
	new.Global.LanInterface = []string{"eth2", "eth3"}
	if !bpfDatapathChanged(old, new) {
		t.Fatal("expected LanInterface change to trigger datapath change")
	}
}

func TestBpfDatapathChanged_WanInterface(t *testing.T) {
	old := baseConfig()
	new := baseConfig()
	new.Global.WanInterface = []string{"ppp0"}
	if !bpfDatapathChanged(old, new) {
		t.Fatal("expected WanInterface change to trigger datapath change")
	}
}

func TestBpfDatapathChanged_BpfConnStateMapSize(t *testing.T) {
	old := baseConfig()
	new := baseConfig()
	new.Global.BpfConnStateMapSize = 65536
	if !bpfDatapathChanged(old, new) {
		t.Fatal("expected BpfConnStateMapSize change to trigger datapath change")
	}
}

func TestBpfDatapathChanged_SoMarkFromDae(t *testing.T) {
	old := baseConfig()
	new := baseConfig()
	new.Global.SoMarkFromDae = 0x100
	if !bpfDatapathChanged(old, new) {
		t.Fatal("expected SoMarkFromDae change to trigger datapath change")
	}
}

func TestBpfDatapathChanged_DNSRoutingChange(t *testing.T) {
	old := baseConfig()
	new := baseConfig()
	new.Dns.Upstream = []config.KeyableString{"8.8.8.8"}
	if !bpfDatapathChanged(old, new) {
		t.Fatal("expected DNS upstream change to trigger datapath change")
	}
}

func TestBuildPreparedDNSHandoffHooksReuseHookReusesControllerAndListener(t *testing.T) {
	var reuseControllerCalls int
	var reuseListenerCalls int
	hooks := buildPreparedDNSHandoffHooks(newDiscardLogger(), true, preparedDNSHandoffHookCallbacks{
		reuseController: func() bool {
			reuseControllerCalls++
			return true
		},
		reuseListener: func() bool {
			reuseListenerCalls++
			return true
		},
	})
	if hooks.reuseHook == nil {
		t.Fatal("reuseHook = nil, want non-nil")
	}
	if err := hooks.reuseHook(); err != nil {
		t.Fatalf("reuseHook() error = %v", err)
	}
	if reuseControllerCalls != 1 {
		t.Fatalf("reuseControllerCalls = %d, want 1", reuseControllerCalls)
	}
	if reuseListenerCalls != 1 {
		t.Fatalf("reuseListenerCalls = %d, want 1", reuseListenerCalls)
	}
}

func TestBuildPreparedDNSHandoffHooksStartHookStopsOldListenerWhenReuseFails(t *testing.T) {
	var stopCalls int
	hooks := buildPreparedDNSHandoffHooks(newDiscardLogger(), false, preparedDNSHandoffHookCallbacks{
		reuseListener: func() bool { return false },
		stopOldListener: func() error {
			stopCalls++
			return nil
		},
	})
	if hooks.startHook == nil {
		t.Fatal("startHook = nil, want non-nil")
	}
	if err := hooks.startHook(); err != nil {
		t.Fatalf("startHook() error = %v", err)
	}
	if stopCalls != 1 {
		t.Fatalf("stopCalls = %d, want 1", stopCalls)
	}
}

func TestBuildPreparedDNSHandoffHooksStartHookPropagatesStopError(t *testing.T) {
	wantErr := errors.New("stop failed")
	hooks := buildPreparedDNSHandoffHooks(newDiscardLogger(), false, preparedDNSHandoffHookCallbacks{
		reuseListener:   func() bool { return false },
		stopOldListener: func() error { return wantErr },
	})
	if err := hooks.startHook(); !errors.Is(err, wantErr) {
		t.Fatalf("startHook() error = %v, want %v", err, wantErr)
	}
}

func TestReloadManagerStartControlPlaneRetirementCompletesAndCancelsOldContext(t *testing.T) {
	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	manager.setPendingReloadMetadata(time.Now(), 0)

	oldCtx, oldCancel := context.WithCancel(context.Background())
	manager.startControlPlaneRetirement(newDiscardLogger(), &control.ControlPlane{}, nil, oldCancel, false, false)

	manager.mu.Lock()
	retirementDone := manager.pendingRetirementDone
	manager.mu.Unlock()
	if retirementDone == nil {
		t.Fatal("pendingRetirementDone = nil, want retirement completion channel")
	}

	select {
	case <-retirementDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for retirement goroutine to finish")
	}

	select {
	case <-oldCtx.Done():
	default:
		t.Fatal("expected old generation cancel function to be called")
	}
}

func TestWaitReloadReadyOrSignalReturnsOnReady(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	readyChan := make(chan bool, 1)
	readyChan <- true

	result, termSig := waitReloadReadyOrSignal(newDiscardLogger(), sigs, readyChan, time.Second)
	if result != reloadReadyWaitReady {
		t.Fatalf("result = %v, want reloadReadyWaitReady", result)
	}
	if termSig != nil {
		t.Fatalf("termSig = %v, want nil", termSig)
	}
}

func TestWaitReloadReadyOrSignalReturnsOnTerminationSignal(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	readyChan := make(chan bool)
	sigs <- syscall.SIGINT

	result, termSig := waitReloadReadyOrSignal(newDiscardLogger(), sigs, readyChan, time.Second)
	if result != reloadReadyWaitSignal {
		t.Fatalf("result = %v, want reloadReadyWaitSignal", result)
	}
	if termSig != syscall.SIGINT {
		t.Fatalf("termSig = %v, want SIGINT", termSig)
	}
}

func TestWaitReloadReadyOrSignalIgnoresReloadSignalsUntilReady(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	readyChan := make(chan bool, 1)
	sigs <- syscall.SIGUSR1

	go func() {
		time.Sleep(10 * time.Millisecond)
		readyChan <- true
	}()

	result, termSig := waitReloadReadyOrSignal(newDiscardLogger(), sigs, readyChan, time.Second)
	if result != reloadReadyWaitReady {
		t.Fatalf("result = %v, want reloadReadyWaitReady", result)
	}
	if termSig != nil {
		t.Fatalf("termSig = %v, want nil", termSig)
	}
}

func TestWaitReloadReadyOrSignalReturnsTimeout(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	readyChan := make(chan bool)

	result, termSig := waitReloadReadyOrSignal(newDiscardLogger(), sigs, readyChan, 10*time.Millisecond)
	if result != reloadReadyWaitTimeout {
		t.Fatalf("result = %v, want reloadReadyWaitTimeout", result)
	}
	if termSig != nil {
		t.Fatalf("termSig = %v, want nil", termSig)
	}
}

func TestWaitForControlPlaneDrainReturnsIdleImmediately(t *testing.T) {
	result := waitForControlPlaneDrain(newDiscardLogger(), context.Background(), newFakeRetirementControlPlane(0), time.Second, 0)
	if result != controlPlaneDrainIdle {
		t.Fatalf("result = %v, want controlPlaneDrainIdle", result)
	}
}

func TestWaitForControlPlaneDrainReturnsIdleAfterSignal(t *testing.T) {
	plane := newFakeRetirementControlPlane(1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		atomic.StoreInt32(&plane.active, 0)
		close(plane.idleCh)
	}()

	result := waitForControlPlaneDrain(newDiscardLogger(), context.Background(), plane, time.Second, 0)
	if result != controlPlaneDrainIdle {
		t.Fatalf("result = %v, want controlPlaneDrainIdle", result)
	}
}

func TestWaitForControlPlaneDrainReturnsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	plane := newFakeRetirementControlPlane(1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	result := waitForControlPlaneDrain(newDiscardLogger(), ctx, plane, time.Second, 0)
	if result != controlPlaneDrainCanceled {
		t.Fatalf("result = %v, want controlPlaneDrainCanceled", result)
	}
}

func TestWaitForControlPlaneDrainReturnsTimeout(t *testing.T) {
	result := waitForControlPlaneDrain(newDiscardLogger(), context.Background(), newFakeRetirementControlPlane(1), 10*time.Millisecond, 0)
	if result != controlPlaneDrainTimeout {
		t.Fatalf("result = %v, want controlPlaneDrainTimeout", result)
	}
}

// retirementBehaviorPlane extends fakeRetirementControlPlane with abort
// tracking to prove the three-way retirement precedence rule:
// abort → !overlap → drain.
type retirementBehaviorPlane struct {
	*fakeRetirementControlPlane
	abortCalled atomic.Bool
}

func (r *retirementBehaviorPlane) AbortConnections() error {
	r.abortCalled.Store(true)
	return nil
}

func TestReloadRetirementBehavior(t *testing.T) {
	tests := []struct {
		name        string
		overlap     bool
		abort       bool
		expectDrain bool
	}{
		{"staged_overlap_no_abortfile_graceful", true, false, true},
		{"staged_no_overlap_no_abortfile_immediate_abort", false, false, false},
		{"staged_overlap_abortfile_immediate_abort", true, true, false},
		{"staged_no_overlap_abortfile_immediate_abort", false, true, false},
		{"nonstaged_overlap_no_abortfile_graceful", true, false, true},
		{"nonstaged_no_overlap_no_abortfile_immediate_abort", false, false, false},
		{"nonstaged_overlap_abortfile_immediate_abort", true, true, false},
		{"nonstaged_no_overlap_abortfile_immediate_abort", false, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plane := &retirementBehaviorPlane{
				fakeRetirementControlPlane: newFakeRetirementControlPlane(1),
			}
			done := make(chan struct{})

			go func() {
				defer close(done)
				retireControlPlaneConnections(newDiscardLogger(), context.Background(), plane, tt.abort, tt.overlap, 10*time.Second)
			}()

			if tt.expectDrain {
				select {
				case <-done:
					t.Fatal("graceful retirement completed while drain was still blocked")
				case <-time.After(50 * time.Millisecond):
				}
				atomic.StoreInt32(&plane.active, 0)
				close(plane.idleCh)
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("graceful retirement did not complete after drain release")
				}
			} else {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("immediate-abort retirement did not complete in time")
				}
				if !plane.abortCalled.Load() {
					t.Fatal("expected AbortConnections to be called for immediate-abort case")
				}
			}
		})
	}
}

func TestReloadRetirementAbortsAfterDrainTimeout(t *testing.T) {
	plane := &retirementBehaviorPlane{
		fakeRetirementControlPlane: newFakeRetirementControlPlane(1),
	}

	retireControlPlaneConnections(newDiscardLogger(), context.Background(), plane, false, true, 10*time.Millisecond)

	if !plane.abortCalled.Load() {
		t.Fatal("expected AbortConnections to be called after drain timeout")
	}
}

func TestReloadRetirementAbortsAfterDrainCancel(t *testing.T) {
	plane := &retirementBehaviorPlane{
		fakeRetirementControlPlane: newFakeRetirementControlPlane(1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	retireControlPlaneConnections(newDiscardLogger(), ctx, plane, false, true, time.Second)

	if !plane.abortCalled.Load() {
		t.Fatal("expected AbortConnections to be called after drain cancellation")
	}
}
