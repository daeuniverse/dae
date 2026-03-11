/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org
 */

package lifecycle

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/mohae/deepcopy"
	"github.com/sirupsen/logrus"
)

type serveHandle struct {
	plane    *control.ControlPlane
	listener *control.Listener
	ready    chan bool
	done     chan struct{}

	mu  sync.RWMutex
	err error
}

func newServeHandle(plane *control.ControlPlane, listener *control.Listener) *serveHandle {
	return &serveHandle{
		plane:    plane,
		listener: listener,
		ready:    make(chan bool, 1),
		done:     make(chan struct{}),
	}
}

func (h *serveHandle) finish(err error) {
	h.mu.Lock()
	h.err = err
	h.mu.Unlock()
	close(h.done)
}

func (h *serveHandle) Err() error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.err
}

// ControlPlaneBridge bridges the LifecycleManager with the existing control.ControlPlane.
// It wraps the existing control plane and provides lifecycle-aware operations.
type ControlPlaneBridge struct {
	log *logrus.Logger

	mu              sync.RWMutex
	plane           *control.ControlPlane
	listener        *control.Listener
	serve           *serveHandle
	pendingBPF      any
	pendingDNSCache map[string]*control.DnsCache
	reuseListener   bool

	ready     chan struct{}
	readyOnce sync.Once

	stopping     chan struct{}
	stoppingOnce sync.Once

	runtimeErrCh chan error

	// Configuration
	cfgFile        string
	externGeoDirs  []string
	pprofServer    *http.Server
	pprofAddr      string
	pidFile        string
	disablePidFile bool
	drainTimeout   time.Duration
	cleanShutdown  bool
}

// NewControlPlaneBridge creates a new bridge to the existing control plane.
func NewControlPlaneBridge(log *logrus.Logger) *ControlPlaneBridge {
	return &ControlPlaneBridge{
		log:          log,
		ready:        make(chan struct{}),
		stopping:     make(chan struct{}),
		runtimeErrCh: make(chan error, 1),
	}
}

// SetConfig sets the configuration for the bridge.
func (b *ControlPlaneBridge) SetConfig(cfgFile string, externGeoDirs []string, drainTimeout time.Duration, cleanShutdown bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cfgFile = cfgFile
	b.externGeoDirs = externGeoDirs
	b.drainTimeout = drainTimeout
	b.cleanShutdown = cleanShutdown
}

// SetPidFile configures pidfile handling.
func (b *ControlPlaneBridge) SetPidFile(pidFile string, disable bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pidFile = pidFile
	b.disablePidFile = disable
}

// SetPprof configures pprof server.
func (b *ControlPlaneBridge) SetPprof(addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pprofAddr = addr
}

func (b *ControlPlaneBridge) RuntimeErrors() <-chan error {
	return b.runtimeErrCh
}

// Precheck validates that the system is ready for dae to start.
func (b *ControlPlaneBridge) Precheck(ctx context.Context, genID string, req *StartRequest) error {
	b.log.Infof("[%s] Precheck phase", genID)

	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (or use sudo)")
	}

	if _, err := os.Stat(req.ConfigFile); os.IsNotExist(err) {
		return &PrecheckError{
			LifecycleError: LifecycleError{
				Op:    "start",
				Phase: string(PhasePrecheck),
				ID:    genID,
				Cause: fmt.Errorf("config file not found: %s", req.ConfigFile),
			},
			ChecksFailed: []string{"config_file"},
		}
	}
	return nil
}

// Prepare creates the control plane with all necessary resources.
func (b *ControlPlaneBridge) Prepare(ctx context.Context, genID string, req *StartRequest) (*Generation, error) {
	b.log.Infof("[%s] Prepare phase", genID)

	if req.Config == nil {
		return nil, fmt.Errorf("config not provided in StartRequest")
	}

	b.mu.RLock()
	purgeStale := b.plane == nil
	b.mu.RUnlock()

	conf, plane, err := b.buildPlane(ctx, req.Config, req.ConfigFile, req.ExternGeoDataDirs, nil, nil, purgeStale)
	if err != nil {
		return nil, err
	}

	gen := NewGeneration(genID, conf, ComputeConfigHash(conf))
	gen.Owned = &OwnedResources{
		ControlPlane: plane,
	}
	return gen, nil
}

// Attach binds the control plane to network interfaces.
func (b *ControlPlaneBridge) Attach(ctx context.Context, gen *Generation) error {
	b.log.Infof("[%s] Attach phase", gen.ID)
	b.log.Info("eBPF programs attached to network interfaces")
	return nil
}

// Activate starts the listeners and signals readiness.
func (b *ControlPlaneBridge) Activate(ctx context.Context, gen *Generation) error {
	b.log.Infof("[%s] Activate phase", gen.ID)

	if gen.Config == nil {
		return fmt.Errorf("generation has no config")
	}
	plane, err := controlPlaneFromGeneration(gen)
	if err != nil {
		return err
	}

	listener, err := b.listenInNetns(plane, gen.Config.Global.TproxyPort)
	if err != nil {
		return err
	}
	gen.Owned.TProxyListener = listener

	if err := plane.StartDNSListener(); err != nil {
		return fmt.Errorf("start dns listener: %w", err)
	}

	serve := newServeHandle(plane, listener)
	go func() {
		serve.finish(plane.Serve(serve.ready, listener))
	}()
	if err := b.waitServeReady(ctx, serve, 30*time.Second); err != nil {
		return err
	}

	pprofServer, pprofErr := b.startPprofServer(gen.Config.Global.PprofPort)
	if pprofErr != nil {
		b.log.WithError(pprofErr).Warn("Failed to start pprof server")
	}
	if !b.disablePidFile && b.pidFile != "" {
		pid := os.Getpid()
		if err := os.WriteFile(b.pidFile, []byte(strconv.Itoa(pid)), 0644); err != nil {
			if pprofServer != nil {
				_ = b.shutdownPprofServer(pprofServer)
			}
			return fmt.Errorf("write pidfile: %w", err)
		}
		b.log.Infof("pidfile written: %s", b.pidFile)
	}

	b.activateRuntime(plane, listener, serve, pprofServer)
	b.readyOnce.Do(func() { close(b.ready) })
	b.log.Infof("tproxy listener started on port %d", gen.Config.Global.TproxyPort)
	return nil
}

// ValidateReload determines the reload type and validates the new config.
func (b *ControlPlaneBridge) ValidateReload(ctx context.Context, oldGen *Generation, req *ReloadRequest) (ReloadType, error) {
	b.log.Infof("[%s -> ?] Validate phase", oldGen.ID)

	oldCfg := oldGen.Config
	newCfg := req.Config.(*config.Config)
	if NeedsFullReload(oldCfg, newCfg) {
		b.log.Info("Full reload required (config changed)")
		return ReloadTypeFull, nil
	}

	b.log.Info("Config-only reload (routing rules changed)")
	return ReloadTypeConfigOnly, nil
}

// PrepareReload prepares the new generation for reload.
func (b *ControlPlaneBridge) PrepareReload(ctx context.Context, genID string, oldGen *Generation, req *ReloadRequest) (*Generation, error) {
	b.log.Infof("[%s] Prepare phase (reload type: %s)", genID, req.ReloadType)

	oldCfg := oldGen.Config
	newCfg := req.Config.(*config.Config)
	if oldCfg == nil || newCfg == nil {
		return nil, fmt.Errorf("reload config is nil")
	}

	b.mu.RLock()
	oldPlane := b.plane
	b.mu.RUnlock()
	if oldPlane == nil {
		return nil, fmt.Errorf("no active control plane")
	}

	portChanged := oldCfg.Global.TproxyPort != newCfg.Global.TproxyPort
	var dnsCache map[string]*control.DnsCache
	if CompatibleForConfigOnlyReload(oldCfg, newCfg) {
		dnsCache = oldPlane.CloneDnsCache()
	} else {
		b.log.Info("DNS cache incompatible; clearing cache")
	}

	var reusedBPF any
	if !portChanged {
		reusedBPF = oldPlane.EjectBpf()
	}
	buildDNSCache := dnsCache
	if reusedBPF != nil {
		buildDNSCache = nil
	}

	conf, newPlane, err := b.buildPlane(ctx, newCfg, b.cfgFile, b.externGeoDirs, reusedBPF, buildDNSCache, false)
	if err != nil {
		if reusedBPF != nil {
			_ = oldPlane.AttachBpf(reusedBPF)
		}
		return nil, fmt.Errorf("new control plane: %w", err)
	}

	newGen := NewGeneration(genID, conf, ComputeConfigHash(conf))
	newGen.Owned = &OwnedResources{
		ControlPlane: newPlane,
	}
	if portChanged {
		listener, err := b.listenInNetns(newPlane, conf.Global.TproxyPort)
		if err != nil {
			if reusedBPF != nil {
				_ = oldPlane.AttachBpf(reusedBPF)
			}
			return nil, fmt.Errorf("prepare new listener: %w", err)
		}
		newGen.Owned.TProxyListener = listener
	}

	b.mu.Lock()
	b.pendingBPF = reusedBPF
	b.pendingDNSCache = dnsCache
	b.reuseListener = !portChanged
	b.mu.Unlock()
	return newGen, nil
}

// Cutover performs the atomic switch to the new generation.
func (b *ControlPlaneBridge) Cutover(ctx context.Context, oldGen, newGen *Generation, req *ReloadRequest) error {
	b.log.Infof("[%s -> %s] Cutover phase", oldGen.ID, newGen.ID)

	newPlane, err := controlPlaneFromGeneration(newGen)
	if err != nil {
		return err
	}

	b.mu.RLock()
	oldPlane := b.plane
	oldListener := b.listener
	oldServe := b.serve
	oldPprof := b.pprofServer
	reusedBPF := b.pendingBPF
	pendingDNSCache := b.pendingDNSCache
	reuseListener := b.reuseListener
	b.mu.RUnlock()

	if oldPlane == nil || oldListener == nil || oldServe == nil {
		return fmt.Errorf("active runtime is incomplete")
	}

	if req.AbortConns {
		if err := oldPlane.AbortConnections(); err != nil {
			b.log.WithError(err).Warn("AbortConnections before cutover failed")
		}
	}

	b.mu.Lock()
	if b.serve == oldServe {
		b.serve = nil
	}
	if b.plane == oldPlane {
		b.plane = nil
	}
	if b.listener == oldListener {
		b.listener = nil
	}
	if b.pprofServer == oldPprof {
		b.pprofServer = nil
	}
	b.mu.Unlock()

	if oldPprof != nil {
		if err := b.shutdownPprofServer(oldPprof); err != nil {
			b.log.WithError(err).Warn("Failed to stop old pprof server")
		}
	}
	if err := oldPlane.Close(); err != nil {
		b.log.WithError(err).Warn("Failed to close old control plane during cutover")
	}
	if err := b.waitServeExit(ctx, oldServe, 5*time.Second, "old listener to stop"); err != nil {
		return err
	}

	listener := oldListener
	if !reuseListener {
		if oldListener != nil {
			if err := oldListener.Close(); err != nil {
				b.log.WithError(err).Warn("Failed to close old listener during port switch")
			}
		}
		var ok bool
		listener, ok = newGen.Owned.TProxyListener.(*control.Listener)
		if !ok || listener == nil {
			return fmt.Errorf("new listener not prepared")
		}
	}
	newGen.Owned.TProxyListener = listener

	if reusedBPF != nil {
		if err := newPlane.ApplyReloadState(pendingDNSCache); err != nil {
			return fmt.Errorf("apply reload state: %w", err)
		}
	}
	if reusedBPF != nil {
		if err := newPlane.AttachBpf(reusedBPF); err != nil {
			return fmt.Errorf("attach reused bpf to new control plane: %w", err)
		}
	}
	if err := newPlane.StartDNSListener(); err != nil {
		return fmt.Errorf("start new dns listener: %w", err)
	}

	serve := newServeHandle(newPlane, listener)
	go func() {
		serve.finish(newPlane.Serve(serve.ready, listener))
	}()
	if err := b.waitServeReady(ctx, serve, 30*time.Second); err != nil {
		_ = newPlane.StopDNSListener()
		return err
	}

	pprofServer, pprofErr := b.startPprofServer(newGen.Config.Global.PprofPort)
	if pprofErr != nil {
		b.log.WithError(pprofErr).Warn("Failed to start pprof server")
	}

	b.mu.Lock()
	b.pendingBPF = nil
	b.pendingDNSCache = nil
	b.reuseListener = false
	b.mu.Unlock()
	b.activateRuntime(newPlane, listener, serve, pprofServer)
	return nil
}

// Rollback attempts to restore the old generation on cutover failure.
func (b *ControlPlaneBridge) Rollback(ctx context.Context, oldGen, newGen *Generation, req *ReloadRequest) error {
	b.log.Infof("[%s -> %s] Rollback phase", newGen.ID, oldGen.ID)

	b.mu.Lock()
	reusedBPF := b.pendingBPF
	b.pendingBPF = nil
	b.pendingDNSCache = nil
	b.reuseListener = false
	oldPlane := b.plane
	b.mu.Unlock()

	if reusedBPF != nil && oldPlane != nil {
		if err := oldPlane.AttachBpf(reusedBPF); err != nil {
			return fmt.Errorf("restore bpf ownership: %w", err)
		}
	}
	return nil
}

// DrainOld drains resources from the old generation after successful cutover.
func (b *ControlPlaneBridge) DrainOld(ctx context.Context, oldGen *Generation) error {
	b.log.Infof("[%s] DrainOld phase", oldGen.ID)
	return nil
}

// StopAccepting stops accepting new connections.
func (b *ControlPlaneBridge) StopAccepting(ctx context.Context, gen *Generation) error {
	b.log.Infof("[%s] StopAccepting phase", gen.ID)

	b.stoppingOnce.Do(func() {
		close(b.stopping)
	})

	b.mu.Lock()
	listener := b.listener
	plane := b.plane
	pprofServer := b.pprofServer
	b.serve = nil
	b.listener = nil
	b.pprofServer = nil
	b.mu.Unlock()

	if listener != nil {
		if err := listener.Close(); err != nil {
			b.log.WithError(err).Warn("Failed to close listener")
		}
	}
	if plane != nil {
		if err := plane.StopDNSListenerFast(); err != nil {
			b.log.WithError(err).Warn("Failed to stop DNS listener")
		}
	}
	if pprofServer != nil {
		if err := b.closePprofServer(pprofServer); err != nil {
			b.log.WithError(err).Warn("Failed to stop pprof server")
		}
	}
	return nil
}

// Drain waits for established connections to finish.
func (b *ControlPlaneBridge) Drain(ctx context.Context, gen *Generation, timeout time.Duration) error {
	b.mu.RLock()
	plane := b.plane
	b.mu.RUnlock()
	if plane == nil {
		return nil
	}

	const shortDrainTimeout = 500 * time.Millisecond
	b.log.Debugf("[%s] Drain phase (short wait: %v)", gen.ID, shortDrainTimeout)
	select {
	case <-time.After(shortDrainTimeout):
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// AbortConnections aborts established connections immediately.
func (b *ControlPlaneBridge) AbortConnections(ctx context.Context, gen *Generation) {
	b.log.Infof("[%s] Abort connections", gen.ID)

	b.mu.RLock()
	plane := b.plane
	b.mu.RUnlock()
	if plane != nil {
		if err := plane.AbortConnections(); err != nil {
			b.log.WithError(err).Warn("AbortConnections failed")
		}
	}
}

// Release releases resources in layered order.
func (b *ControlPlaneBridge) Release(ctx context.Context, gen *Generation) error {
	b.log.Infof("[%s] Release phase", gen.ID)

	b.mu.Lock()
	plane := b.plane
	listener := b.listener
	b.plane = nil
	b.listener = nil
	b.pendingBPF = nil
	b.pendingDNSCache = nil
	b.reuseListener = false
	b.mu.Unlock()

	var errs []error
	if plane != nil {
		if err := plane.AbortConnections(); err != nil {
			errs = append(errs, err)
		}
		if err := plane.CloseFast(); err != nil {
			errs = append(errs, err)
		}
	}
	if listener != nil {
		if err := listener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("release errors: %v", errs)
	}
	return nil
}

// FinalCleanup performs final cleanup operations.
func (b *ControlPlaneBridge) FinalCleanup(ctx context.Context, gen *Generation) error {
	b.log.Infof("[%s] FinalCleanup phase", gen.ID)

	if !b.disablePidFile && b.pidFile != "" {
		if err := os.Remove(b.pidFile); err != nil && !os.IsNotExist(err) {
			b.log.WithError(err).Warn("Failed to remove pidfile")
		}
	}
	if b.cleanShutdown {
		if err := control.GetDaeNetns().Close(); err != nil {
			b.log.WithError(err).Warn("Failed to close dae netns")
		}
	}
	_ = os.Remove("/var/run/dae.progress")
	_ = os.Remove("/var/run/dae.abort")
	return nil
}

// GetControlPlane returns the current control plane.
func (b *ControlPlaneBridge) GetControlPlane() *control.ControlPlane {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.plane
}

// WaitForReady waits until the control plane is ready.
func (b *ControlPlaneBridge) WaitForReady(ctx context.Context) error {
	select {
	case <-b.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(30 * time.Second):
		return fmt.Errorf("timeout waiting for control plane ready")
	}
}

// IsStopping returns true if stop signal was sent.
func (b *ControlPlaneBridge) IsStopping() bool {
	select {
	case <-b.stopping:
		return true
	default:
		return false
	}
}

// checkPortAvailability checks if the tproxy port is available.
func (b *ControlPlaneBridge) checkPortAvailability(port uint16) error {
	addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(int(port)))
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("port %d unavailable: %w", port, err)
	}
	conn.Close()
	return nil
}

func (b *ControlPlaneBridge) buildPlane(
	ctx context.Context,
	conf *config.Config,
	cfgFile string,
	externGeoDataDirs []string,
	bpf any,
	dnsCache map[string]*control.DnsCache,
	purgeStale bool,
) (*config.Config, *control.ControlPlane, error) {
	cloned, ok := deepcopy.Copy(conf).(*config.Config)
	if !ok || cloned == nil {
		return nil, nil, fmt.Errorf("deep copy config failed")
	}

	direct.InitDirectDialers(cloned.Global.FallbackResolver)
	fallbackAddr, err := netip.ParseAddrPort(cloned.Global.FallbackResolver)
	if err != nil {
		return nil, nil, fmt.Errorf("parse fallback resolver: %w", err)
	}
	netutils.FallbackDns = fallbackAddr

	tagToNodeList, err := b.resolveSubscriptions(ctx, cloned, &StartRequest{
		ConfigFile:        cfgFile,
		ExternGeoDataDirs: externGeoDataDirs,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("resolve subscriptions: %w", err)
	}

	if purgeStale && bpf == nil {
		control.PurgeStaleTCFilters(b.log)
	}
	if err := b.preprocessWanInterfaceAuto(cloned); err != nil {
		return nil, nil, fmt.Errorf("preprocess wan interface auto: %w", err)
	}

	plane, err := control.NewControlPlane(
		b.log,
		bpf,
		dnsCache,
		tagToNodeList,
		cloned.Group,
		&cloned.Routing,
		&cloned.Global,
		&cloned.Dns,
		externGeoDataDirs,
		&control.NewControlPlaneOption{
			StartDNSListener: false,
			ApplyReloadState: bpf == nil,
		},
	)
	if err != nil {
		return nil, nil, err
	}
	return cloned, plane, nil
}

func controlPlaneFromGeneration(gen *Generation) (*control.ControlPlane, error) {
	if gen == nil || gen.Owned == nil || gen.Owned.ControlPlane == nil {
		return nil, fmt.Errorf("generation has no control plane")
	}
	plane, ok := gen.Owned.ControlPlane.(*control.ControlPlane)
	if !ok || plane == nil {
		return nil, fmt.Errorf("unexpected control plane type: %T", gen.Owned.ControlPlane)
	}
	return plane, nil
}

func (b *ControlPlaneBridge) listenInNetns(plane *control.ControlPlane, port uint16) (*control.Listener, error) {
	var listener *control.Listener
	if err := control.GetDaeNetns().WithRequired("listen in dae netns", func() error {
		var err error
		listener, err = plane.Listen(port)
		return err
	}); err != nil {
		return nil, err
	}
	return listener, nil
}

func (b *ControlPlaneBridge) waitServeReady(ctx context.Context, serve *serveHandle, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case ready := <-serve.ready:
		if ready {
			return nil
		}
		if err := b.waitServeExit(ctx, serve, 5*time.Second, "serve startup failure"); err != nil {
			return err
		}
		if err := serve.Err(); err != nil {
			return err
		}
		return fmt.Errorf("listener failed before ready")
	case <-serve.done:
		if err := serve.Err(); err != nil {
			return err
		}
		return fmt.Errorf("listener exited before ready")
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("timeout waiting for listener to be ready")
	}
}

func (b *ControlPlaneBridge) waitServeExit(ctx context.Context, serve *serveHandle, timeout time.Duration, what string) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-serve.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("timeout waiting for %s", what)
	}
}

func (b *ControlPlaneBridge) activateRuntime(plane *control.ControlPlane, listener *control.Listener, serve *serveHandle, pprofServer *http.Server) {
	b.mu.Lock()
	b.plane = plane
	b.listener = listener
	b.serve = serve
	b.pprofServer = pprofServer
	b.mu.Unlock()

	go b.watchServe(serve)
}

func (b *ControlPlaneBridge) watchServe(serve *serveHandle) {
	<-serve.done

	b.mu.RLock()
	active := b.serve == serve
	b.mu.RUnlock()
	if !active {
		return
	}

	err := serve.Err()
	if err == nil {
		err = fmt.Errorf("tproxy listener exited unexpectedly")
	}
	select {
	case b.runtimeErrCh <- err:
	default:
		if b.log != nil {
			b.log.WithError(err).Error("runtime error channel is full")
		}
	}
}

func (b *ControlPlaneBridge) startPprofServer(port uint16) (*http.Server, error) {
	if port == 0 {
		return nil, nil
	}

	addr := fmt.Sprintf("localhost:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen pprof: %w", err)
	}

	server := &http.Server{Handler: nil}
	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			b.log.WithError(err).Warn("pprof server error")
		}
	}()
	b.log.Infof("pprof server listening on %s", addr)
	return server, nil
}

func (b *ControlPlaneBridge) shutdownPprofServer(server *http.Server) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

func (b *ControlPlaneBridge) closePprofServer(server *http.Server) error {
	return server.Close()
}

// resolveSubscriptions resolves subscription URLs to node lists.
func (b *ControlPlaneBridge) resolveSubscriptions(ctx context.Context, conf *config.Config, req *StartRequest) (map[string][]string, error) {
	tagToNodeList := map[string][]string{}

	// Add direct nodes
	if len(conf.Node) > 0 {
		for _, node := range conf.Node {
			tagToNodeList[""] = append(tagToNodeList[""], string(node))
		}
	}

	// No subscriptions to resolve
	if len(conf.Subscription) == 0 {
		return tagToNodeList, nil
	}

	// Wait for network if not disabled
	if !conf.Global.DisableWaitingNetwork {
		b.log.Info("Waiting for network...")
		if err := b.waitForNetwork(ctx, conf); err != nil {
			b.log.Warnf("Network check failed: %v", err)
		} else {
			b.log.Info("Network online")
		}
	}

	// Resolve subscriptions
	b.log.Info("Fetching subscriptions...")
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
				conn, err := direct.SymmetricDirect.DialContext(ctx, common.MagicNetwork("tcp", conf.Global.SoMarkFromDae, conf.Global.Mptcp), addr)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  conn,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
		},
		Timeout: 30 * time.Second,
	}

	cfgFileDir := filepath.Dir(req.ConfigFile)
	resolvingfailed := false

	for _, sub := range conf.Subscription {
		tag, nodes, err := subscription.ResolveSubscription(b.log, client, cfgFileDir, string(sub))
		if err != nil {
			b.log.Warnf("Failed to resolve subscription \"%v\": %v", sub, err)
			resolvingfailed = true
			continue
		}
		if len(nodes) > 0 {
			tagToNodeList[tag] = append(tagToNodeList[tag], nodes...)
			b.log.Infof("Subscription \"%s\" resolved with %d nodes", tag, len(nodes))
		}
	}

	// Clean up stale persist.d files
	persistDir := filepath.Join(cfgFileDir, "persist.d")
	files, err := os.ReadDir(persistDir)
	if err != nil && !os.IsNotExist(err) {
		return tagToNodeList, nil
	}
	for _, file := range files {
		tag := strings.TrimSuffix(file.Name(), ".sub")
		if _, ok := tagToNodeList[tag]; !ok {
			_ = os.Remove(filepath.Join(persistDir, file.Name()))
		}
	}

	if resolvingfailed {
		b.log.Warn("Some subscriptions failed to resolve")
	}

	return tagToNodeList, nil
}

// waitForNetwork waits for network connectivity.
func (b *ControlPlaneBridge) waitForNetwork(ctx context.Context, conf *config.Config) error {
	const (
		checkTimeout = 5 * time.Second
		maxAttempts  = 60 // Try for up to 5 minutes
	)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
				conn, err := direct.SymmetricDirect.DialContext(ctx, common.MagicNetwork("tcp", conf.Global.SoMarkFromDae, conf.Global.Mptcp), addr)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  conn,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
		},
		Timeout: checkTimeout,
	}

	// Network check links (same as in run.go)
	checkLinks := []string{
		"http://edge.microsoft.com/captiveportal/generate_204",
		"http://www.gstatic.com/generate_204",
		"http://www.qualcomm.cn/generate_204",
	}

	for i := 0; i < maxAttempts; i++ {
		link := checkLinks[i%len(checkLinks)]
		resp, err := client.Get(link)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				return nil
			}
		}
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return fmt.Errorf("network not available after %d attempts", maxAttempts)
}

// Close releases all resources held by the bridge.
func (b *ControlPlaneBridge) Close() error {
	b.mu.Lock()
	plane := b.plane
	listener := b.listener
	pprofServer := b.pprofServer
	b.plane = nil
	b.listener = nil
	b.serve = nil
	b.pprofServer = nil
	b.pendingBPF = nil
	b.pendingDNSCache = nil
	b.reuseListener = false
	b.mu.Unlock()

	var errs []error
	if pprofServer != nil {
		if err := b.shutdownPprofServer(pprofServer); err != nil {
			errs = append(errs, err)
		}
	}
	if plane != nil {
		if err := plane.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if listener != nil {
		if err := listener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}

// preprocessWanInterfaceAuto converts "auto" in WanInterface to actual interface names.
// This matches the behavior in cmd/run.go.
func (b *ControlPlaneBridge) preprocessWanInterfaceAuto(conf *config.Config) error {
	ifs := make([]string, 0, len(conf.Global.WanInterface)+2)
	for _, ifname := range conf.Global.WanInterface {
		if ifname == "auto" {
			defaultIfs, err := common.GetDefaultIfnames()
			if err != nil {
				return fmt.Errorf("failed to convert 'auto': %w", err)
			}
			ifs = append(ifs, defaultIfs...)
		} else {
			ifs = append(ifs, ifname)
		}
	}
	conf.Global.WanInterface = common.Deduplicate(ifs)
	return nil
}
