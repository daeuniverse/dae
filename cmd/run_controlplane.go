/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/mohae/deepcopy"
	"golang.org/x/sys/unix"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/component/daedns"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
)

func listenControlPlaneInDaeNetns(c *control.ControlPlane, port uint16) (*control.Listener, error) {
	var listener *control.Listener
	err := withDaeNetnsRequiredFunc("listen control plane", func() error {
		var listenErr error
		listener, listenErr = listenControlPlaneFunc(c, port)
		return listenErr
	})
	if err != nil {
		if listener != nil {
			if closeErr := listener.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close listener after netns failure: %w", closeErr))
			}
		}
		return nil, fmt.Errorf("listen in dae netns: %w", err)
	}
	if listener == nil {
		return nil, fmt.Errorf("listen in dae netns: listener is nil")
	}
	return listener, nil
}

func newControlPlane(ctx context.Context, log *logrus.Logger, bpf any, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string, dnsRoutingUnchanged bool, isReloadBuild bool) (c *control.ControlPlane, err error) {
	return newControlPlaneWithMode(ctx, log, bpf, dnsCache, conf, externGeoDataDirs, false, dnsRoutingUnchanged, isReloadBuild)
}

func newPreparedControlPlane(ctx context.Context, log *logrus.Logger, bpf any, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string, dnsRoutingUnchanged bool, isReloadBuild bool) (c *control.ControlPlane, err error) {
	return newControlPlaneWithMode(ctx, log, bpf, dnsCache, conf, externGeoDataDirs, true, dnsRoutingUnchanged, isReloadBuild)
}

// buildControlPlaneRuntime is the final construction boundary after config
// normalization, subscription resolution, and reload safety checks. The
// prepareOnly × isReloadBuild matrix folds into build options: prepared
// candidates delay both the datapath commit and the DNS listener start, and
// any reload build (or an inherited BPF handle) selects reload-mode flipping.
func buildControlPlaneRuntime(
	ctx context.Context,
	log *logrus.Logger,
	bpf any,
	dnsCache map[string]*control.DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routing *config.Routing,
	global *config.Global,
	dns *config.Dns,
	directDialer netproxy.Dialer,
	fullconeDirectDialer netproxy.Dialer,
	systemDNSResolver *netutils.SystemDNSResolver,
	externGeoDataDirs []string,
	prepareOnly bool,
	dnsRoutingUnchanged bool,
	isReloadBuild bool,
) (*control.ControlPlane, error) {
	return control.NewControlPlaneWithContextOptions(
		ctx,
		log,
		bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routing,
		global,
		dns,
		externGeoDataDirs,
		control.ControlPlaneBuildOptions{
			DelayDatapathCommit:   prepareOnly,
			DelayDNSListenerStart: prepareOnly,
			DNSRoutingUnchanged:   dnsRoutingUnchanged,
			IsReload:              isReloadBuild || bpf != nil,
			DirectDialer:          directDialer,
			FullconeDirectDialer:  fullconeDirectDialer,
			SystemDNSResolver:     systemDNSResolver,
		},
	)
}

func configureTransparentHugePages(log *logrus.Logger, disable bool) {
	value := uintptr(0)
	action := "enable"
	if disable {
		value = 1
		action = "disable"
	}

	if err := unix.Prctl(unix.PR_SET_THP_DISABLE, value, 0, 0, 0); err != nil {
		if log != nil {
			log.WithError(err).Warnf("Failed to %s transparent huge pages for dae process", action)
		}
		return
	}
	if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
		log.Debugf("Configured transparent huge pages for dae process: disable=%v", disable)
	}
}

// configureGcMemoryLimit auto-detects the cgroup v2 memory ceiling for the
// current process and sets GOMEMLIMIT to 90% of it. This lets the Go runtime
// GC proactively release memory before hitting the container/system limit,
// which is critical for containerized deployments where GOGC's default
// (100% heap growth) can overshoot the cgroup limit and trigger OOM kills.
//
// An explicit GOMEMLIMIT always wins. Only memory.max participates in the
// detected ceiling: memory.high is a reclaim throttle the kernel lets the
// process exceed, so deriving a soft heap limit from it makes the Go GC run
// back-to-back against a threshold that was never meant to be a hard bound.
// The function is a no-op when no finite cgroup ceiling is configured.
func configureGcMemoryLimit(log *logrus.Logger) {
	if value, ok := os.LookupEnv("GOMEMLIMIT"); ok {
		if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
			log.Debugf("GOMEMLIMIT: using explicit environment value %q", value)
		}
		return
	}
	limit := detectCgroupMemLimit()
	if limit <= 0 {
		if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
			log.Debug("GOMEMLIMIT: no finite cgroup memory ceiling detected, skipping")
		}
		return
	}
	// Reserve 10% headroom for non-Go allocations (eBPF maps, goroutine stacks, etc.)
	softLimit := limit * 9 / 10
	debug.SetMemoryLimit(softLimit)
	if log != nil {
		log.Infof("Configured GOMEMLIMIT=%d MiB (cgroup memory ceiling=%d MiB)",
			softLimit/1024/1024, limit/1024/1024)
	}
}

func newControlPlaneWithMode(ctx context.Context, log *logrus.Logger, bpf any, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string, prepareOnly bool, dnsRoutingUnchanged bool, isReloadBuild bool) (c *control.ControlPlane, err error) {
	// Deep copy to prevent modification.
	conf = deepcopy.Copy(conf).(*config.Config)
	if conf.Global.SoMarkFromDae == 0 {
		var autoSelected bool
		conf.Global.SoMarkFromDae, autoSelected = common.ResolveSoMarkFromDae(conf.Global.SoMarkFromDae, conf.Global.SoMarkFromDaeSet)
		if autoSelected {
			// This is the reachable, user-visible report of the auto-selected
			// mark: every control-plane build goes through this function
			// (startup and both reload paths), and it resolves the mark before
			// control.NewControlPlane sees the config. The same warning exists
			// in control.NewControlPlane as a defensive guard for callers that
			// bypass cmd; with this resolution upstream its autoSelected branch
			// is unreachable from the daemon, so it double-reports nothing.
			log.Warnf("so_mark_from_dae is unset; using internal socket mark %#x to prevent dae UDP self-capture", conf.Global.SoMarkFromDae)
		}
	}

	/// Get tag -> nodeList mapping.
	tagToNodeList := map[string][]string{}
	// On initial startup (not reload), purge stale TC filters left by any previous process.
	if bpf == nil && !isReloadBuild {
		control.PurgeStaleTCFilters(log)
	}
	if len(conf.Node) > 0 {
		for _, node := range conf.Node {
			tagToNodeList[""] = append(tagToNodeList[""], string(node))
		}
	}

	/// Build generation-scoped direct dialers.
	directDialers := direct.NewDirectDialers(conf.Global.FallbackResolver)
	systemDNSResolver := netutils.NewSystemDNSResolver(netip.MustParseAddrPort(conf.Global.FallbackResolver))
	locationFinder := assets.NewLocationFinder(externGeoDataDirs)
	daeDNSRouter, err := daedns.NewWithOption(log, &conf.Global, &conf.Dns, &daedns.NewOption{
		LocationFinder: locationFinder,
		DirectDialer:   directDialers.Symmetric,
	})
	if err != nil {
		return nil, err
	}
	if daeDNSRouter != nil {
		defer func() { _ = daeDNSRouter.Close() }()
	}

	// Start timing the startup process
	startTime := time.Now()
	// Reused across phases; each stage resets it right before its work.
	var stageStart time.Time

	// Resolve subscriptions to nodes.
	resolvingfailed := false
	if !conf.Global.DisableWaitingNetwork {
		networkWaitStart := time.Now()
		epo := 5 * time.Second
		client := http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
					conn, err := directDialers.Symmetric.DialContext(ctx, common.MagicNetwork("tcp", conf.Global.SoMarkFromDae, conf.Global.Mptcp), addr)
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
			Timeout: epo,
		}
		log.Infoln("Waiting for network...")
		attempts, online, err := waitForNetworkOnline(ctx, &client, log, CheckNetworkLinks, epo, networkWaitTimeout)
		if err != nil {
			return nil, err
		}
		if online {
			log.Infoln("Network online.")
		} else {
			log.Warnf("Network still unreachable after %v (%d attempt(s)); resolving subscriptions anyway so local nodes keep working. Check the network, or set disable_waiting_network: true to skip this wait.", networkWaitTimeout, attempts)
		}
		log.Infof("Network check took %v (%d attempt(s))", time.Since(networkWaitStart), attempts)
	}
	if len(conf.Subscription) > 0 {
		log.Infoln("Fetching subscriptions...")
	}
	// Parallelize subscription resolution to improve startup performance.
	// Use a semaphore to limit concurrency and avoid overwhelming the network.
	type subscriptionResult struct {
		tag     string
		nodes   []string
		err     error
		sub     config.KeyableString
		elapsed time.Duration
	}
	numSubscriptions := len(conf.Subscription)
	if numSubscriptions > 0 {
		// Reset to cover only the fetch itself; the network-wait phase above is
		// timed separately, so slow WAN bring-up no longer shows up as
		// "Subscriptions fetched".
		stageStart = time.Now()
		// Limit concurrency to 4 subscriptions at a time to avoid overwhelming network
		maxConcurrency := min(numSubscriptions, 4)
		sem := make(chan struct{}, maxConcurrency)
		results := make(chan subscriptionResult, numSubscriptions)

		for _, sub := range conf.Subscription {
			go func(s config.KeyableString) {
				sem <- struct{}{}        // Acquire semaphore
				defer func() { <-sem }() // Release semaphore

				subStart := time.Now()
				subDialer := directDialers.Symmetric
				if daeDNSRouter != nil {
					wrappedDialer, wrapErr := daeDNSRouter.WrapSubscriptionDialer(subDialer, string(s))
					if wrapErr != nil {
						results <- subscriptionResult{
							err: wrapErr,
							sub: s,
						}
						return
					}
					subDialer = wrappedDialer
				}
				client := newHTTPClientForDialer(subDialer, 30*time.Second, conf.Global.SoMarkFromDae, conf.Global.Mptcp)
				tag, nodes, err := subscription.ResolveSubscription(log, &client, filepath.Dir(cfgFile), string(s))
				results <- subscriptionResult{
					tag:     tag,
					nodes:   nodes,
					err:     err,
					sub:     s,
					elapsed: time.Since(subStart),
				}
			}(sub)
		}

		// Collect results
		for range numSubscriptions {
			result := <-results
			if result.err != nil {
				log.Warnf(`failed to resolve subscription "%v" after %v: %v`, result.sub, result.elapsed, result.err)
				resolvingfailed = true
			} else {
				log.Infof(`subscription "%v" resolved %d node(s) in %v`, result.tag, len(result.nodes), result.elapsed)
			}
			if len(result.nodes) > 0 {
				tagToNodeList[result.tag] = append(tagToNodeList[result.tag], result.nodes...)
			}
		}
		close(results)
		log.Infof("Subscriptions fetched in %v", time.Since(stageStart))
	}

	// Delete all files in persist.d that are not in tagToNodeList
	files, err := os.ReadDir(filepath.Join(filepath.Dir(cfgFile), "persist.d"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, file := range files {
		tag := strings.TrimSuffix(file.Name(), ".sub")
		if _, ok := tagToNodeList[tag]; !ok {
			err := os.Remove(filepath.Join(filepath.Dir(cfgFile), "persist.d", file.Name()))
			if err != nil {
				return nil, err
			}
		}
	}

	if len(tagToNodeList) == 0 {
		if resolvingfailed {
			log.Warnln("No node found because all subscription resolving failed.")
		} else {
			log.Warnln("No node found.")
		}
	}

	// On reload, refuse to switch to a dead (zero-node) generation when every
	// subscription failed to resolve. Without this guard the caller's rollback
	// path is never taken (a zero-node build is not an error by itself), so dae
	// would silently cut all proxied traffic until a full restart. The persisted
	// cache in persist.d normally shields against transient failures, but when
	// it is also missing/empty this guard is the last line of defense.
	//
	// A successful-but-empty fetch (subscription legitimately returned 0 nodes)
	// is left alone — resolvingfailed is only set on a hard fetch error, so an
	// intentional zero-node config is unaffected. Initial startup is also
	// excluded: there is no previous generation to preserve.
	if isReloadBuild && resolvingfailed && len(tagToNodeList) == 0 {
		return nil, fmt.Errorf("refusing reload with 0 nodes: all subscription resolving failed; keeping the current generation")
	}

	if len(conf.Global.LanInterface) == 0 && len(conf.Global.WanInterface) == 0 {
		// Deliberately warn, not error, and this is a decision with a stated
		// invalidation condition: dae binds interfaces lazily. bindLan/bindWan
		// register a pattern with the InterfaceManager and attach whenever a
		// matching link appears (see controlPlaneCore.logBindOutcome), so
		// "no interface at this instant" is recoverable - a container whose
		// veth is created after dae starts, or a WAN link that appears when
		// the modem comes up, would be reported as a fatal startup error while
		// the daemon would in fact have bound it moments later.
		//
		// This must become an error if that lazy path ever stops delivering
		// link events for a configured pattern (for example if the interface
		// subscription is removed, or if a caller can reach this point with an
		// empty LanInterface while no lan_interface default exists), because
		// then "no interface" really is permanent and dae would run with an
		// empty datapath instead of failing closed.
		log.Warnln("No interface to bind.")
	}

	if err = preprocessWanInterfaceAuto(conf); err != nil {
		return nil, err
	}

	// Start timing the control plane creation
	log.Infoln("Building control plane and routing rules...")
	stageStart = time.Now()
	c, err = buildControlPlaneRuntime(
		ctx,
		log,
		bpf,
		dnsCache,
		tagToNodeList,
		conf.Group,
		&conf.Routing,
		&conf.Global,
		&conf.Dns,
		directDialers.Symmetric,
		directDialers.Fullcone,
		systemDNSResolver,
		externGeoDataDirs,
		prepareOnly,
		dnsRoutingUnchanged,
		isReloadBuild,
	)
	if err != nil {
		return nil, err
	}
	log.Infof("Control plane built in %v", time.Since(stageStart))
	log.Infof("Total startup time: %v", time.Since(startTime))

	return c, nil
}
