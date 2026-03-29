/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/direct"
	dnsmessage "github.com/miekg/dns"
	"github.com/panjf2000/ants/v2"
	"github.com/sirupsen/logrus"
)

const Timeout = 10 * time.Second

type NetworkType struct {
	L4Proto   consts.L4ProtoStr
	IpVersion consts.IpVersionStr
	IsDns     bool
}

func (t *NetworkType) String() string {
	if t.IsDns {
		return t.StringWithoutDns() + "(DNS)"
	} else {
		return t.StringWithoutDns()
	}
}

func (t *NetworkType) StringWithoutDns() string {
	return string(t.L4Proto) + string(t.IpVersion)
}

// Index returns the collection index for this network type.
//
// Design Note: TCP DNS (IsDns=true, L4Proto=TCP) and plain TCP (IsDns=false, L4Proto=TCP)
// share the same collection index (IdxTcp4 or IdxTcp6). This is intentional because:
//  1. TCP DNS and plain TCP are identical at the transport layer - both are TCP connections.
//  2. A successful HTTP/TCP health check indicates the dialer can establish TCP connections
//     for both DNS-over-TCP and plain TCP traffic.
//  3. This consolidation eliminates redundant probes, reducing network overhead and memory usage.
//
// In contrast, UDP DNS uses separate indices (IdxDnsUdp4/IdxDnsUdp6) because UDP health checks
// perform actual DNS queries, which test a different code path than plain UDP (which is rarely
// used directly and typically shares DNS check results anyway).
func (t *NetworkType) Index() int {
	switch t.L4Proto {
	case consts.L4ProtoStr_TCP:
		switch t.IpVersion {
		case consts.IpVersionStr_4:
			return IdxTcp4
		case consts.IpVersionStr_6:
			return IdxTcp6
		}
	case consts.L4ProtoStr_UDP:
		switch t.IpVersion {
		case consts.IpVersionStr_4:
			return IdxDnsUdp4
		case consts.IpVersionStr_6:
			return IdxDnsUdp6
		}
	}
	panic("invalid network type")
}

type collection struct {
	// AliveDialerSetSet uses reference counting.
	AliveDialerSetSet AliveDialerSetSet
	Latencies10       *LatenciesN
	MovingAverage     time.Duration
	Alive             atomic.Bool
}

func newCollection() *collection {
	c := &collection{
		AliveDialerSetSet: make(AliveDialerSetSet),
		Latencies10:       NewLatenciesN(10),
	}
	c.Alive.Store(true)
	return c
}

func (d *Dialer) mustGetCollection(typ *NetworkType) *collection {
	return d.collections[typ.Index()]
}

func (d *Dialer) MustGetAlive(typ *NetworkType) bool {
	return d.mustGetCollection(typ).Alive.Load()
}

type collectionUpdate struct {
	alive             bool
	movingAverage     time.Duration
	aliveDialerGroups []*AliveDialerSet
}

func (d *Dialer) hasAliveDialerSets(typ *NetworkType) bool {
	d.collectionFineMu.RLock()
	has := len(d.mustGetCollection(typ).AliveDialerSetSet) > 0
	d.collectionFineMu.RUnlock()
	return has
}

func (d *Dialer) snapshotLatencyForPolicy(
	typ *NetworkType,
	policy consts.DialerSelectionPolicy,
) (rawLatency time.Duration, hasLatency bool) {
	d.collectionFineMu.RLock()
	collection := d.mustGetCollection(typ)
	switch policy {
	case consts.DialerSelectionPolicy_MinLastLatency:
		rawLatency, hasLatency = collection.Latencies10.LastLatency()
	case consts.DialerSelectionPolicy_MinAverage10Latencies:
		rawLatency, hasLatency = collection.Latencies10.AvgLatency()
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		rawLatency = collection.MovingAverage
		hasLatency = rawLatency > 0
	}
	d.collectionFineMu.RUnlock()

	if hasLatency {
		rawLatency += d.GetBackoffPenalty(typ.L4Proto)
	}
	return rawLatency, hasLatency
}


func (d *Dialer) snapshotAliveDialerGroupsLocked(collection *collection) []*AliveDialerSet {
	if len(collection.AliveDialerSetSet) == 0 {
		return nil
	}
	groups := make([]*AliveDialerSet, 0, len(collection.AliveDialerSetSet))
	for a := range collection.AliveDialerSetSet {
		groups = append(groups, a)
	}
	return groups
}

func parseIp46FromList(ip []string) *netutils.Ip46 {
	ip46 := new(netutils.Ip46)
	for _, ip := range ip {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if addr.Is4() || addr.Is4In6() {
			ip46.Ip4 = addr
		} else if addr.Is6() {
			ip46.Ip6 = addr
		}
	}
	return ip46
}

type TcpCheckOption struct {
	Url *netutils.URL
	*netutils.Ip46
	Method string
}

func ParseTcpCheckOption(ctx context.Context, rawURL []string, method string, resolverNetwork string) (opt *TcpCheckOption, err error) {
	if method == "" {
		method = http.MethodGet
	}
	systemDns, err := netutils.SystemDns()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = netutils.TryUpdateSystemDnsElapse(time.Second)
		}
	}()

	if len(rawURL) == 0 {
		return nil, fmt.Errorf("ParseTcpCheckOption: bad format: empty")
	}
	u, err := url.Parse(rawURL[0])
	if err != nil {
		return nil, err
	}
	var ip46 *netutils.Ip46
	if len(rawURL) > 1 {
		ip46 = parseIp46FromList(rawURL[1:])
	} else {
		ip46, _, _ = netutils.ResolveIp46(ctx, direct.SymmetricDirect, systemDns, u.Hostname(), resolverNetwork, false)
		if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
			return nil, fmt.Errorf("ResolveIp46: no valid ip for %v", u.Hostname())
		}
	}
	return &TcpCheckOption{
		Url:    &netutils.URL{URL: u},
		Ip46:   ip46,
		Method: method,
	}, nil
}

type CheckDnsOption struct {
	DnsHost string
	DnsPort uint16
	*netutils.Ip46
}

func ParseCheckDnsOption(ctx context.Context, dnsHostPort []string, resolverNetwork string) (opt *CheckDnsOption, err error) {
	systemDns, err := netutils.SystemDns()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = netutils.TryUpdateSystemDnsElapse(time.Second)
		}
	}()

	if len(dnsHostPort) == 0 {
		return nil, fmt.Errorf("ParseCheckDnsOption: bad format: empty")
	}

	host, _port, err := net.SplitHostPort(dnsHostPort[0])
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(_port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("bad port: %v", err)
	}
	var ip46 *netutils.Ip46
	if len(dnsHostPort) > 1 {
		ip46 = parseIp46FromList(dnsHostPort[1:])
	} else {
		ip46, _, _ = netutils.ResolveIp46(ctx, direct.SymmetricDirect, systemDns, host, resolverNetwork, false)
		if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
			return nil, fmt.Errorf("ResolveIp46: no valid ip for %v", host)
		}
	}
	return &CheckDnsOption{
		DnsHost: host,
		DnsPort: uint16(port),
		Ip46:    ip46,
	}, nil
}

type TcpCheckOptionRaw struct {
	opt             *TcpCheckOption
	mu              sync.Mutex
	Log             *logrus.Logger
	Raw             []string
	ResolverNetwork string
	Method          string
}

func (c *TcpCheckOptionRaw) Option() (opt *TcpCheckOption, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		ctx, cancel := context.WithTimeout(context.Background(), Timeout)
		defer cancel()
		type contextKey string
		ctx = context.WithValue(ctx, contextKey("logger"), c.Log)
		tcpCheckOption, err := ParseTcpCheckOption(ctx, c.Raw, c.Method, c.ResolverNetwork)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tcp_check_url: %w", err)
		}
		c.opt = tcpCheckOption
	}
	return c.opt, nil
}

type CheckDnsOptionRaw struct {
	opt             *CheckDnsOption
	mu              sync.Mutex
	Raw             []string
	ResolverNetwork string
	Somark          uint32
}

func (c *CheckDnsOptionRaw) Option() (opt *CheckDnsOption, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		ctx, cancel := context.WithTimeout(context.Background(), Timeout)
		defer cancel()
		udpCheckOption, err := ParseCheckDnsOption(ctx, c.Raw, c.ResolverNetwork)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tcp_check_url: %w", err)
		}
		c.opt = udpCheckOption
	}
	return c.opt, nil
}

type CheckOption struct {
	networkType *NetworkType
	CheckFunc   func(ctx context.Context, typ *NetworkType) (ok bool, err error)
}

func (d *Dialer) ActivateCheck() {
	d.tickerMu.Lock()
	defer d.tickerMu.Unlock()
	if d.DisableCheck || d.checkActivated {
		return
	}
	d.checkActivated = true
	go d.aliveBackground()
}

// Global connectivity check worker pool
var (
	connectivityCheckPool *ants.Pool
	poolMu                sync.Mutex
	poolActiveCount       int
)

// calcPoolSize scales the pool sub-linearly with the number of active dialers
// so cold-start throughput grows with fleet size without goroutine explosion.
// Formula: clamp(40 + ceil(sqrt(nodes)*10), 40, 256)
func calcPoolSize(nodes int) int {
	if nodes <= 0 {
		return 40
	}
	size := 40 + int(math.Ceil(math.Sqrt(float64(nodes))*10))
	if size > 256 {
		return 256
	}
	return size
}

// getConnectivityCheckPool returns the global worker pool.
// The pool pointer is stable (Tune never replaces it), so callers may
// capture it once before entering a loop.
func getConnectivityCheckPool() *ants.Pool {
	poolMu.Lock()
	defer poolMu.Unlock()
	return connectivityCheckPool
}

// registerConnectivityCheckDialer increments the active-dialer count and
// lazily initialises or grows the worker pool via Tune.
func registerConnectivityCheckDialer() {
	poolMu.Lock()
	defer poolMu.Unlock()
	poolActiveCount++
	size := calcPoolSize(poolActiveCount)
	if connectivityCheckPool == nil {
		// No WithPreAlloc: lazy allocation lets Tune() resize freely.
		p, err := ants.NewPool(size)
		if err != nil {
			panic("failed to initialize ants pool for connectivity check: " + err.Error())
		}
		connectivityCheckPool = p
	} else {
		connectivityCheckPool.Tune(size)
	}
}

// releaseConnectivityCheckDialer decrements the active-dialer count and
// tunes the pool down accordingly.
func releaseConnectivityCheckDialer() {
	poolMu.Lock()
	defer poolMu.Unlock()
	if poolActiveCount > 0 {
		poolActiveCount--
	}
	if connectivityCheckPool != nil {
		connectivityCheckPool.Tune(calcPoolSize(poolActiveCount))
	}
}

func getActiveDialerCount() int {
	poolMu.Lock()
	defer poolMu.Unlock()
	return poolActiveCount
}

func (d *Dialer) aliveBackground() {
	cycle := d.CheckInterval
	var tcpSomark uint32
	var mptcp bool
	if network, err := netproxy.ParseMagicNetwork(d.TcpCheckOptionRaw.ResolverNetwork); err == nil {
		tcpSomark = network.Mark
		mptcp = network.Mptcp
	}
	tcp4CheckOpt := &CheckOption{
		networkType: &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_4,
			IsDns:     false,
		},
		CheckFunc: func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
			opt, err := d.TcpCheckOptionRaw.Option()
			if err != nil {
				return false, err
			}
			if !opt.Ip4.IsValid() {
				d.Log.WithFields(logrus.Fields{
					"link":    d.TcpCheckOptionRaw.Raw,
					"dialer":  d.property.Name,
					"network": typ.String(),
				}).Debugln("Skip check due to no DNS record.")
				return false, nil
			}
			return d.HttpCheck(ctx, IdxTcp4, opt.Url, opt.Ip4, opt.Method, tcpSomark, mptcp)
		},
	}
	tcp6CheckOpt := &CheckOption{
		networkType: &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_6,
			IsDns:     false,
		},
		CheckFunc: func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
			opt, err := d.TcpCheckOptionRaw.Option()
			if err != nil {
				return false, err
			}
			if !opt.Ip6.IsValid() {
				d.Log.WithFields(logrus.Fields{
					"link":    d.TcpCheckOptionRaw.Raw,
					"dialer":  d.property.Name,
					"network": typ.String(),
				}).Debugln("Skip check due to no DNS record.")
				return false, nil
			}
			return d.HttpCheck(ctx, IdxTcp6, opt.Url, opt.Ip6, opt.Method, tcpSomark, mptcp)
		},
	}
	udpNetwork := netproxy.MagicNetwork{
		Network: "udp",
		Mark:    d.CheckDnsOptionRaw.Somark,
	}.Encode()
	// makeDnsCheckFunc returns a CheckFunc for DNS connectivity checks.
	// The ip selector selects Ip4 or Ip6 from the option; network is the encoded
	// magic network string (tcpNetwork or udpNetwork).
	// This factory eliminates the verbatim duplication across the 4 DNS CheckOption blocks.
	makeDnsCheckFunc := func(
		ip func(opt *CheckDnsOption) netip.Addr,
		network *string,
	) func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
		return func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
			opt, err := d.CheckDnsOptionRaw.Option()
			if err != nil {
				return false, err
			}
			addr := ip(opt)
			if !addr.IsValid() {
				d.Log.WithFields(logrus.Fields{
					"link":    d.CheckDnsOptionRaw.Raw,
					"network": typ.String(),
				}).Debugln("Skip check due to no DNS record.")
				return false, nil
			}
			return d.DnsCheck(ctx, netip.AddrPortFrom(addr, opt.DnsPort), *network)
		}
	}

	udp4CheckDnsOpt := &CheckOption{
		networkType: &NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_4,
			IsDns:     true,
		},
		CheckFunc: makeDnsCheckFunc(func(o *CheckDnsOption) netip.Addr { return o.Ip4 }, &udpNetwork),
	}
	udp6CheckDnsOpt := &CheckOption{
		networkType: &NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_6,
			IsDns:     true,
		},
		CheckFunc: makeDnsCheckFunc(func(o *CheckDnsOption) netip.Addr { return o.Ip6 }, &udpNetwork),
	}
	var CheckOpts = []*CheckOption{tcp4CheckOpt, tcp6CheckOpt, udp4CheckDnsOpt, udp6CheckDnsOpt}

	var unusedOnce bool
	checkUnused := func() bool {
		var unused int
		for _, opt := range CheckOpts {
			if !d.hasAliveDialerSets(opt.networkType) {
				unused++
			}
		}
		if unused == len(CheckOpts) {
			if !unusedOnce {
				d.Log.WithField("dialer", d.Property().Name).
					WithField("p", unsafe.Pointer(d)).
					Debugln("dialer connectivity check is sleeping due to unused")
				unusedOnce = true
			}
			return true
		}
		unusedOnce = false
		return false
	}

	_ = checkUnused()

	registerConnectivityCheckDialer()

	// Cold-start stagger: spread initial checks to avoid thundering herd.
	//
	// Problem: timer=0 fires all N dialers at once, causing a connection spike
	// through proxy servers. Overloaded proxies fail health checks → Alive=false
	// → handleUDP tears down UDP endpoints → ErrNoAliveDialer → packet loss.
	//
	// Solution: use poolActiveCount (the dialer's registration index) to give
	// each dialer a progressively wider jitter window:
	//   window = clamp(index * 50ms, 1s, cycle/4)
	// For 10 nodes:  ≤500ms → fires within 1s (minimum floor)
	// For 100 nodes: ≤5s    → first results within ~5s
	// For 1000 nodes: capped at cycle/4 (e.g. 7.5s for 30s cycle)
	//
	// After the first check completes we re-spread within the full cycle
	// so steady-state checks are evenly distributed.
	coldStartWindow := time.Duration(getActiveDialerCount()) * 50 * time.Millisecond
	if maxWindow := cycle / 4; coldStartWindow > maxWindow {
		coldStartWindow = maxWindow
	}
	if coldStartWindow < time.Second {
		coldStartWindow = time.Second
	}
	d.tickerMu.Lock()
	d.ticker = time.NewTimer(time.Duration(fastrand.Int63n(int64(coldStartWindow))))
	d.tickerMu.Unlock()
	defer func() {
		d.tickerMu.Lock()
		if d.ticker != nil {
			d.ticker.Stop()
			d.ticker = nil
		}
		d.checkActivated = false
		d.tickerMu.Unlock()
		releaseConnectivityCheckDialer()
		d.Log.WithField("dialer", d.Property().Name).
			WithField("p", unsafe.Pointer(d)).
			Traceln("cleaned up connectivity check goroutine")
	}()

	var wg sync.WaitGroup
	// Pool pointer is stable (Tune never replaces it); capture once.
	workerPool := getConnectivityCheckPool()
	isFirstCheck := true

	for {
		// Check if the dialer is still useful. If not, exit the goroutine.
		if checkUnused() {
			return
		}

		// checkFamily is non-empty when triggered by NotifyCheckUdp/NotifyCheckTcp:
		// only the matching check opts are run (both IPv4 and IPv6), and the
		// periodic ticker is left untouched so the regular schedule is not disrupted.
		var checkFamily consts.L4ProtoStr
		var cycleRes *cycleResult
		select {
		case <-d.ctx.Done():
			return
		case <-d.ticker.C:
		case <-d.checkCh:
		case <-d.checkUdpCh:
			checkFamily = consts.L4ProtoStr_UDP
		case <-d.checkTcpCh:
			checkFamily = consts.L4ProtoStr_TCP
		}

		opts := CheckOpts
		if checkFamily != "" {
			// Targeted check: run all checks matching the triggered protocol family (v4 + v6).
			opts = filterCheckOptsByFamily(CheckOpts, checkFamily)
		} else {
			// Full check: advance the sticky IP cache cycle to allow IP failover.
			d.IncrementCheckCycle()
			cycleRes = &cycleResult{}
		}

		d.submitCheckTasks(workerPool, &wg, opts, checkFamily != "", cycleRes)
		wg.Wait()
		if checkFamily == "" {
			// Stability-based wash white: only reset stability if a protocol family had failures
			// WITHOUT any successes in this cycle. This allows partially-working dual-stack
			// nodes (e.g. V4 OK, V6 broken) to eventually wash white their penalty.
			d.NotifyPeriodicCheckResult(consts.L4ProtoStr_TCP, cycleRes.tcpSuccess, cycleRes.tcpFailure && !cycleRes.tcpSuccess)
			d.NotifyPeriodicCheckResult(consts.L4ProtoStr_UDP, cycleRes.udpSuccess, cycleRes.udpFailure && !cycleRes.udpSuccess)
		}

		// Targeted checks don't disturb the periodic timer — only full checks do.
		if checkFamily != "" {
			continue
		}

		// After the cold-start check completes, re-spread once within the
		// cycle window so dialers don't all enter steady-state at the same
		// phase offset. Subsequent checks strictly honour check_interval.
		nextDelay := cycle
		if isFirstCheck {
			nextDelay = time.Duration(fastrand.Int63n(int64(cycle)))
			isFirstCheck = false
		}
		d.tickerMu.Lock()
		if d.ticker != nil {
			// Stop and drain before Reset: if the select was woken by checkCh,
			// a pending timer tick would cause a spurious immediate re-check.
			if !d.ticker.Stop() {
				select {
				case <-d.ticker.C:
				default:
				}
			}
			d.ticker.Reset(nextDelay)
		}
		d.tickerMu.Unlock()
	}
}

// filterCheckOptsByFamily returns the subset of opts whose networkType matches
// the given proto family. Both data and DNS probes are included for the family.
func filterCheckOptsByFamily(opts []*CheckOption, family consts.L4ProtoStr) []*CheckOption {
	var result []*CheckOption
	for _, opt := range opts {
		if opt.networkType.L4Proto == family {
			result = append(result, opt)
		}
	}
	return result
}

// submitCheckTasks submits check tasks to worker pool
func (d *Dialer) submitCheckTasks(workerPool *ants.Pool, wg *sync.WaitGroup, opts []*CheckOption, isResuscitation bool, cycle *cycleResult) {
	for _, opt := range opts {
		// No need to test if there is no dialer selection policy using its latency.
		if !d.hasAliveDialerSets(opt.networkType) {
			continue
		}

		wg.Add(1)
		checkOpt := opt
		err := workerPool.Submit(func() {
			defer wg.Done()
			if isResuscitation {
				// Stagger resuscitation probes to prevent thundering herd.
				// Random delay between 0 and 2 seconds.
				time.Sleep(time.Duration(fastrand.Int63n(int64(2 * time.Second))))
			}
			_, _ = d.check(checkOpt, isResuscitation, cycle)
		})

		if err != nil {
			// If pool is closed or errors out, fallback to goroutine to ensure check proceeds
			go func() {
				defer wg.Done()
				_, _ = d.check(checkOpt, isResuscitation, cycle)
			}()
		}
	}
}

// NotifyCheck will succeed only when CheckEnabled is true.
func (d *Dialer) NotifyCheck() {
	select {
	case <-d.ctx.Done():
		return
	default:
	}

	select {
	// If fail to push elem to chan, the check is in process.
	case d.checkCh <- time.Now():
	default:
	}
}

// NotifyCheckUdp triggers a targeted health check for all UDP collections (IPv4 and IPv6).
func (d *Dialer) NotifyCheckUdp() {
	select {
	case <-d.ctx.Done():
		return
	default:
	}

	// 2s cooldown for emergency probes to protect the worker pool.
	now := time.Now().UnixNano()
	pre := d.lastNotifyUdp.Load()
	if now-pre < int64(2*time.Second) {
		return
	}
	if !d.lastNotifyUdp.CompareAndSwap(pre, now) {
		return
	}

	select {
	case d.checkUdpCh <- struct{}{}:
	default:
	}
}

// NotifyCheckTcp triggers a targeted health check for all TCP collections (IPv4 and IPv6).
func (d *Dialer) NotifyCheckTcp() {
	select {
	case <-d.ctx.Done():
		return
	default:
	}

	// 2s cooldown for emergency probes to protect the worker pool.
	now := time.Now().UnixNano()
	pre := d.lastNotifyTcp.Load()
	if now-pre < int64(2*time.Second) {
		return
	}
	if !d.lastNotifyTcp.CompareAndSwap(pre, now) {
		return
	}

	select {
	case d.checkTcpCh <- struct{}{}:
	default:
	}
}

func (d *Dialer) MustGetLatencies10(typ *NetworkType) *LatenciesN {
	return d.mustGetCollection(typ).Latencies10
}

// RegisterAliveDialerSet is thread-safe.
func (d *Dialer) RegisterAliveDialerSet(a *AliveDialerSet) {
	if a == nil {
		return
	}
	d.collectionFineMu.Lock()
	d.mustGetCollection(a.CheckTyp).AliveDialerSetSet[a]++
	d.collectionFineMu.Unlock()
}

// UnregisterAliveDialerSet is thread-safe.
func (d *Dialer) UnregisterAliveDialerSet(a *AliveDialerSet) {
	if a == nil {
		return
	}
	d.collectionFineMu.Lock()
	defer d.collectionFineMu.Unlock()
	setSet := d.mustGetCollection(a.CheckTyp).AliveDialerSetSet
	setSet[a]--
	if setSet[a] <= 0 {
		delete(setSet, a)
	}
}

func (d *Dialer) logUnavailable(
	network *NetworkType,
	err error,
) {
	if err != nil {
		// Use common/errors package for type-safe error checking
		// instead of string matching for better reliability.
		if commonerrors.IsNetworkUnreachable(err) {
			err = fmt.Errorf("network is unreachable")
		} else if commonerrors.IsAddressNotSuitable(err) {
			err = fmt.Errorf("IPv%v is not supported", network.IpVersion)
		}
		d.Log.WithFields(logrus.Fields{
			"network": network.String(),
			"node":    d.property.Name,
			"err":     err.Error(),
		}).Debugln("Connectivity Check Failed")
	}
}

func (d *Dialer) markUnavailable(typ *NetworkType) collectionUpdate {
	return d.markUnavailableInternal(typ, false, false)
}

func (d *Dialer) markUnavailableInternal(typ *NetworkType, force bool, isTraffic bool) collectionUpdate {
	d.collectionFineMu.Lock()
	idx := typ.Index()
	collection := d.collections[idx]
	collection.Latencies10.AppendLatency(Timeout)
	collection.MovingAverage = (collection.MovingAverage + Timeout) / 2

	// UDP/TCP robustness: only mark unavailable after consecutive failures.
	// This protects against transient network interference.
	threshold := 1
	switch typ.L4Proto {
	case consts.L4ProtoStr_UDP:
		if isTraffic {
			// Higher threshold for data traffic to avoid flipping during transient jitter.
			threshold = 50
		}
	case consts.L4ProtoStr_TCP:
		if isTraffic {
			// Balance "fast discovery" of failures with resilience to noise.
			threshold = 10
		}
	}

	alive := false
	if !force {
		if isTraffic {
			d.trafficFailCount[idx].Add(1)
			if int(d.trafficFailCount[idx].Load()) < threshold {
				alive = collection.Alive.Load()
			}
		} else {
			d.failCount[idx]++
			if d.failCount[idx] < threshold {
				alive = collection.Alive.Load()
			}
		}
	} else {
		// Forced death: reset counter to match state.
		d.trafficFailCount[idx].Store(int32(threshold))
		d.failCount[idx] = threshold
	}
	wasAlive := collection.Alive.Load()
	collection.Alive.Store(alive)

	update := collectionUpdate{
		alive:             alive,
		movingAverage:     collection.MovingAverage,
		aliveDialerGroups: d.snapshotAliveDialerGroupsLocked(collection),
	}
	d.collectionFineMu.Unlock()

	// Notify sticky IP dialer and recovery detection ONLY when truly transitioning to dead.
	// This prevents a single failed dialer from repeatedly invalidating the global cache (Sticky Killer).
	// Bypassed for forced death to avoid recursive calls.
	if wasAlive && !alive && !force {
		d.NotifyHealthCheckResult(typ, false, false)
	}

	return update
}

func (d *Dialer) markAvailable(typ *NetworkType, latency time.Duration) (collectionUpdate, time.Duration) {
	d.collectionFineMu.Lock()
	idx := typ.Index()
	collection := d.collections[idx]

	// Synthetic success resets failure counts.
	d.failCount[idx] = 0
	d.trafficFailCount[idx].Store(0)

	collection.Latencies10.AppendLatency(latency)
	avg, _ := collection.Latencies10.AvgLatency()
	collection.MovingAverage = (collection.MovingAverage + latency) / 2
	wasAlive := collection.Alive.Swap(true)
	update := collectionUpdate{
		alive:             true,
		movingAverage:     collection.MovingAverage,
		aliveDialerGroups: d.snapshotAliveDialerGroupsLocked(collection),
	}
	d.collectionFineMu.Unlock()

	// Notify about health check success.
	// isRevival is true if we were dead.
	// We no longer trigger recovery detection for explicit resuscitation probes on already-alive nodes
	// to prevent "self-punishment" (unnecessary level increments).
	isRevival := !wasAlive
	d.NotifyHealthCheckResult(typ, true, isRevival)

	return update, avg
}

func (d *Dialer) informDialerGroupUpdate(update collectionUpdate) {
	for _, a := range update.aliveDialerGroups {
		a.NotifyLatencyChange(d, update.alive)
	}
}

func (d *Dialer) ReportUnavailable(typ *NetworkType, err error) {
	d.logUnavailable(typ, err)
	d.informDialerGroupUpdate(d.markUnavailableInternal(typ, false, true))
}

func (d *Dialer) ReportUnavailableForced(typ *NetworkType, err error) {
	d.logUnavailable(typ, err)
	d.informDialerGroupUpdate(d.markUnavailableInternal(typ, true, true))
}

func (d *Dialer) ReportAvailableTraffic(typ *NetworkType) {
	idx := typ.Index()
	if d.trafficFailCount[idx].Load() != 0 {
		d.trafficFailCount[idx].Store(0)
	}
}

// Check performs a basic connectivity check.
// Backward compatibility wrapper for check(opts, false, nil).
func (d *Dialer) Check(opts *CheckOption) (ok bool, err error) {
	return d.check(opts, false, nil)
}

func (d *Dialer) check(opts *CheckOption, isResuscitation bool, cycle *cycleResult) (ok bool, err error) {
	const maxAttempts = 2
	var bestLatency time.Duration

	for i := 0; i < maxAttempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), Timeout)
		start := time.Now()
		ok, err = opts.CheckFunc(ctx, opts.networkType)
		latency := time.Since(start)
		cancel()

		if ok && err == nil {
			bestLatency = latency
			break
		}
		if err == nil {
			// No applicable IP; skip.
			break
		}
		// Retry on actual error.
	}
	if ok && err == nil {
		// Success: update latency and mark alive.
		update, avg := d.markAvailable(opts.networkType, bestLatency)

		if cycle != nil {
			cycle.Lock()
			if opts.networkType.L4Proto == consts.L4ProtoStr_TCP {
				cycle.tcpSuccess = true
			} else {
				cycle.udpSuccess = true
			}
			cycle.Unlock()
		}

		fields := logrus.Fields{
			"network": opts.networkType.String(),
			"node":    d.property.Name,
			"last":    bestLatency.Truncate(time.Millisecond).String(),
			"avg_10":  avg.Truncate(time.Millisecond),
			"mov_avg": update.movingAverage.Truncate(time.Millisecond),
		}
		if isResuscitation {
			d.Log.WithFields(fields).Infof("%s resuscitated by emergency probe", strings.ToUpper(string(opts.networkType.L4Proto)))
		} else {
			d.Log.WithFields(fields).Debugln("Connectivity Check")
		}
		d.informDialerGroupUpdate(update)
	} else if err != nil {
		// Failure: mark unavailable only if there's an actual error.
		d.logUnavailable(opts.networkType, err)
		d.informDialerGroupUpdate(d.markUnavailable(opts.networkType))

		if cycle != nil {
			cycle.Lock()
			if opts.networkType.L4Proto == consts.L4ProtoStr_TCP {
				cycle.tcpFailure = true
			} else {
				cycle.udpFailure = true
			}
			cycle.Unlock()
		}
	}
	// Skip update when (ok=false, err=nil): preserve existing alive state.
	return ok, err
}

func (d *Dialer) HttpCheck(ctx context.Context, networkIdx int, u *netutils.URL, ip netip.Addr, method string, soMark uint32, mptcp bool) (ok bool, err error) {
	// HTTP(S) check.
	if method == "" {
		method = http.MethodGet
	}
	cli := d.GetHttpClient(networkIdx, ip, soMark, mptcp)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return false, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		var netErr net.Error
		if stderrors.As(err, &netErr); netErr.Timeout() {
			err = fmt.Errorf("timeout")
		}
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Judge the status code.
	if page := path.Base(req.URL.Path); strings.HasPrefix(page, "generate_") {
		if strconv.Itoa(resp.StatusCode) != strings.TrimPrefix(page, "generate_") {
			b, _ := io.ReadAll(resp.Body)
			buf := pool.GetBuffer()
			defer pool.PutBuffer(buf)
			_ = resp.Request.Write(buf)
			d.Log.Debugln(buf.String(), "Resp: ", string(b))
			return false, fmt.Errorf("unexpected status code: %v", resp.StatusCode)
		}
		return true, nil
	} else {
		if resp.StatusCode < 200 || resp.StatusCode >= 500 {
			return false, fmt.Errorf("bad status code: %v", resp.StatusCode)
		}
		return true, nil
	}
}

func (d *Dialer) DnsCheck(ctx context.Context, dns netip.AddrPort, network string) (ok bool, err error) {
	addrs, err := netutils.ResolveNetip(ctx, d, dns, consts.UdpCheckLookupHost, dnsmessage.TypeA, network)
	if err != nil {
		return false, err
	}
	if len(addrs) == 0 {
		return false, fmt.Errorf("bad DNS response: no record")
	}
	return true, nil
}

type cycleResult struct {
	sync.Mutex
	tcpSuccess bool
	tcpFailure bool
	udpSuccess bool
	udpFailure bool
}
