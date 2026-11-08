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
	"github.com/daeuniverse/dae/component/outbound"
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
	nodeDisplayTags map[string]string,
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
	routingTrace bool,
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
			NodeDisplayTags:       nodeDisplayTags,
			RoutingTraceEnabled:   routingTrace,
		},
	)
}

type subscriptionResult struct {
	tag      string
	nodes    []string
	err      error
	sub      config.KeyableString
	elapsed  time.Duration
	stale    bool
	fetchErr error
	payload  []byte
	cacheKey string
}

// newSubscriptionResult carries everything the caller needs from Resolve. The
// payload and cache key must travel with it, or the fetched body is never
// persisted and an outage empties the groups.
func newSubscriptionResult(sub config.KeyableString, resolved subscription.Resolution, err error, elapsed time.Duration) subscriptionResult {
	return subscriptionResult{
		tag:      resolved.Tag,
		nodes:    resolved.Nodes,
		err:      err,
		sub:      sub,
		elapsed:  elapsed,
		stale:    resolved.CacheFallback,
		fetchErr: resolved.FetchErr,
		payload:  resolved.Payload,
		cacheKey: resolved.CacheKey,
	}
}

// fetchedSubscription is one successful fetch whose body has not been persisted
// yet: its links must become dialers first.
type fetchedSubscription struct {
	tag      string
	cacheKey string
	payload  []byte
}

// persistFetchedSubscriptions stores the fetched bodies whose links became
// dialers and reports the tags whose payload produced no usable node. Those
// keep the previous cached copy: persisting them would destroy the last good
// copy a later failed fetch falls back to.
//
// The cache is an optimization, not a requirement: a read-only configuration
// directory must not turn a successful subscription fetch into a startup
// failure. A write error is logged and the generation keeps running without a
// cached copy, exactly like a deployment that never had one.
func persistFetchedSubscriptions(log *logrus.Logger, configDir string, fetched []fetchedSubscription, report map[string]outbound.NodeParseCount) []string {
	var rejected []string
	for _, item := range fetched {
		if count, ok := report[item.tag]; ok && count.Links > 0 && count.Parsed == 0 {
			log.Warnf(`subscription %q returned %d link(s) but none of them could be parsed; keeping the previous cached copy`, item.tag, count.Links)
			rejected = append(rejected, item.tag)
			continue
		}
		if item.cacheKey == "" || len(item.payload) == 0 {
			continue
		}
		if err := subscription.PersistPayload(configDir, item.cacheKey, item.payload); err != nil {
			log.WithError(err).Warnf(`cannot cache subscription %q; keeping the resolved nodes for this generation`, item.tag)
		}
	}
	return rejected
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
	// displayTags keeps subtag() filters and DNS rules on their historical
	// semantics: an untagged subscription is tagless there, while the API still
	// reports it under its own provider identity.
	displayTags := make(map[string]string, len(conf.Subscription))
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
	// Health is reported only for a generation that actually becomes active: a
	// candidate whose build is rejected must not make the running generation
	// look stale.
	subscriptionHealthUpdates := map[string]error{}
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
	// fetched holds the bodies whose links must become dialers before they may
	// replace the cached copy. A payload nobody can load would otherwise
	// destroy the last good copy and empty the groups on the next reload.
	var fetched []fetchedSubscription
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
						wrapTag, _ := common.GetTagFromLinkLikePlaintext(string(s))
						results <- subscriptionResult{
							tag: wrapTag,
							err: wrapErr,
							sub: s,
						}
						return
					}
					subDialer = wrappedDialer
				}
				client := newHTTPClientForDialer(subDialer, 30*time.Second, conf.Global.SoMarkFromDae, conf.Global.Mptcp)
				resolved, err := subscription.Resolve(log, &client, filepath.Dir(cfgFile), string(s))
				results <- newSubscriptionResult(s, resolved, err, time.Since(subStart))
			}(sub)
		}

		// Collect results
		for range numSubscriptions {
			result := <-results
			providerKey := subscription.ProviderKey(result.tag, string(result.sub))
			displayTags[providerKey] = result.tag
			if result.err != nil {
				log.Warnf(`failed to resolve subscription "%v" after %v: %v`, common.RedactURL(string(result.sub)), result.elapsed, common.RedactInlineURLs(result.err.Error()))
				resolvingfailed = true
				subscriptionHealthUpdates[providerKey] = result.err
			} else {
				log.Infof(`subscription "%v" resolved %d node(s) in %v`, result.tag, len(result.nodes), result.elapsed)
				if result.stale {
					// Served from the last good copy: the nodes stay in the
					// generation, but the subscription did not refresh.
					subscriptionHealthUpdates[providerKey] = result.fetchErr
				} else {
					subscriptionHealthUpdates[providerKey] = nil
				}
			}
			if len(result.nodes) > 0 {
				tagToNodeList[providerKey] = append(tagToNodeList[providerKey], result.nodes...)
			}
			if result.err == nil && !result.stale && len(result.payload) > 0 {
				fetched = append(fetched, fetchedSubscription{
					tag:      providerKey,
					cacheKey: result.cacheKey,
					payload:  result.payload,
				})
			}
		}
		close(results)
		log.Infof("Subscriptions fetched in %v", time.Since(stageStart))
	}

	// Delete all files in persist.d that are not in tagToNodeList
	files, err := os.ReadDir(filepath.Join(filepath.Dir(cfgFile), "persist.d"))
	if err != nil {
		if !os.IsNotExist(err) {
			log.WithError(err).Warnln("cannot read the subscription cache directory; continuing without cache maintenance")
		}
		files = nil
	}
	// Delete cached copies of subscriptions that are no longer configured. The
	// key is derived from the configured list, not from tagToNodeList: a
	// subscription that failed on its very first fetch has no nodes, and an
	// untagged one is keyed by its URL, so neither shape appears there.
	liveCacheKeys := make(map[string]struct{}, len(conf.Subscription))
	for _, sub := range conf.Subscription {
		tag, _ := common.GetTagFromLinkLikePlaintext(string(sub))
		liveCacheKeys[subscription.ProviderKey(tag, string(sub))] = struct{}{}
	}
	for _, file := range files {
		key := strings.TrimSuffix(file.Name(), ".sub")
		if _, ok := liveCacheKeys[key]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(filepath.Dir(cfgFile), "persist.d", file.Name())); err != nil {
			log.WithError(err).Warnf("cannot remove stale subscription cache %q; continuing", file.Name())
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
	// The DNS log and the per-flow bookkeeping are only useful while the API
	// can read them, and the direct observer costs datapath time per packet.
	// With api.enabled=false none of them may cost anything, so they follow
	// the API switch; the direct observer additionally needs its own opt-in.
	control.ConfigureDnsLog(conf.Api.Enabled)
	control.ConfigureFlowStats(conf.Api.Enabled)
	control.ConfigureDirectStats(control.ResolveDirectStats(log, conf.Api.Enabled && conf.Api.DirectStats))
	c, err = buildControlPlaneRuntime(
		ctx,
		log,
		bpf,
		dnsCache,
		tagToNodeList,
		displayTags,
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
		conf.Api.Enabled,
	)
	if err != nil {
		return nil, err
	}
	// A subscription body only replaces its cached copy once its links became
	// dialers. A link-shaped payload that produced no dialer would otherwise
	// leave the groups empty while the refresh reported success.
	rejected := persistFetchedSubscriptions(log, filepath.Dir(cfgFile), fetched, c.NodeParseReport())
	if len(rejected) > 0 {
		for _, tag := range rejected {
			subscriptionHealthUpdates[tag] = fmt.Errorf("subscription resolved links but none of them could be parsed; the previous copy is kept")
		}
		if isReloadBuild {
			_ = c.Close()
			return nil, fmt.Errorf(`refusing reload: subscription %q resolved links but no usable node; keeping the current generation`, rejected[0])
		}
	}
	// A reload candidate may still be rejected after this build, so its outcome
	// is shown only once the generation is published. Startup has no previous
	// generation to protect and publishes at once.
	if isReloadBuild {
		c.SetOnPublished(func() { publishSubscriptionHealth(subscriptionHealthUpdates) })
	} else {
		publishSubscriptionHealth(subscriptionHealthUpdates)
	}
	log.Infof("Control plane built in %v", time.Since(stageStart))
	log.Infof("Total startup time: %v", time.Since(startTime))

	return c, nil
}
