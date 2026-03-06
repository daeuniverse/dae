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

func (t *NetworkType) Index() int {
	if t.IsDns {
		switch t.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch t.IpVersion {
			case consts.IpVersionStr_4:
				return IdxDnsTcp4
			case consts.IpVersionStr_6:
				return IdxDnsTcp6
			}
		case consts.L4ProtoStr_UDP:
			switch t.IpVersion {
			case consts.IpVersionStr_4:
				return IdxDnsUdp4
			case consts.IpVersionStr_6:
				return IdxDnsUdp6
			}
		}
	} else {
		switch t.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch t.IpVersion {
			case consts.IpVersionStr_4:
				return IdxTcp4
			case consts.IpVersionStr_6:
				return IdxTcp6
			}
		case consts.L4ProtoStr_UDP:
			// UDP share the DNS check result.
			switch t.IpVersion {
			case consts.IpVersionStr_4:
				return IdxDnsUdp4
			case consts.IpVersionStr_6:
				return IdxDnsUdp6
			}
		}
	}
	panic("invalid network type")
}

type collection struct {
	// AliveDialerSetSet uses reference counting.
	AliveDialerSetSet AliveDialerSetSet
	Latencies10       *LatenciesN
	MovingAverage     time.Duration
	Alive             bool
}

func newCollection() *collection {
	return &collection{
		AliveDialerSetSet: make(AliveDialerSetSet),
		Latencies10:       NewLatenciesN(10),
		Alive:             true,
	}
}

func (d *Dialer) mustGetCollection(typ *NetworkType) *collection {
	return d.collections[typ.Index()]
}

func (d *Dialer) MustGetAlive(typ *NetworkType) bool {
	return d.mustGetCollection(typ).Alive
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
		ctx = context.WithValue(ctx, "logger", c.Log)
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
	if d.InstanceOption.DisableCheck || d.checkActivated {
		return
	}
	d.checkActivated = true
	go d.aliveBackground()
}

// Global connectivity check worker pool
var (
	connectivityCheckPool *ants.Pool
	poolMu               sync.Mutex
	poolActiveCount      int
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
	tcpNetwork := netproxy.MagicNetwork{
		Network: "tcp",
		Mark:    d.CheckDnsOptionRaw.Somark,
	}.Encode()
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

	tcp4CheckDnsOpt := &CheckOption{
		networkType: &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_4,
			IsDns:     true,
		},
		CheckFunc: makeDnsCheckFunc(func(o *CheckDnsOption) netip.Addr { return o.Ip4 }, &tcpNetwork),
	}
	tcp6CheckDnsOpt := &CheckOption{
		networkType: &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_6,
			IsDns:     true,
		},
		CheckFunc: makeDnsCheckFunc(func(o *CheckDnsOption) netip.Addr { return o.Ip6 }, &tcpNetwork),
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
	var CheckOpts = make([]*CheckOption, 6)
	CheckOpts[IdxTcp4] = tcp4CheckOpt
	CheckOpts[IdxTcp6] = tcp6CheckOpt
	CheckOpts[IdxDnsUdp4] = udp4CheckDnsOpt
	CheckOpts[IdxDnsUdp6] = udp6CheckDnsOpt
	CheckOpts[IdxDnsTcp4] = tcp4CheckDnsOpt
	CheckOpts[IdxDnsTcp6] = tcp6CheckDnsOpt

	var unusedOnce bool
	checkUnused := func() bool {
		var unused int
		for _, opt := range CheckOpts {
			if len(d.mustGetCollection(opt.networkType).AliveDialerSetSet) == 0 {
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

	if checkUnused() {
		// Just for early exit if initial state is unused.
		// But we wait for first check below.
	}

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

		select {
		case <-d.ctx.Done():
			return
		case <-d.ticker.C:
		case <-d.checkCh:
		}

		// Process initial check immediately
		d.submitCheckTasks(workerPool, &wg, CheckOpts)

		// Wait for all checks to complete before next cycle
		wg.Wait()

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

// submitCheckTasks submits check tasks to worker pool
func (d *Dialer) submitCheckTasks(workerPool *ants.Pool, wg *sync.WaitGroup, opts []*CheckOption) {
	for _, opt := range opts {
		// No need to test if there is no dialer selection policy using its latency.
		if len(d.collections[opt.networkType.Index()].AliveDialerSetSet) == 0 {
			continue
		}

		wg.Add(1)
		checkOpt := opt
		err := workerPool.Submit(func() {
			defer wg.Done()
			_, _ = d.Check(checkOpt)
		})
		if err != nil {
			// If pool is closed or errors out, fallback to goroutine to ensure check proceeds
			go func() {
				defer wg.Done()
				_, _ = d.Check(checkOpt)
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
	collection *collection,
	network *NetworkType,
	err error,
) {
	// Append timeout if there is any error or unexpected status code.
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
	collection.Latencies10.AppendLatency(Timeout)
	collection.MovingAverage = (collection.MovingAverage + Timeout) / 2
	collection.Alive = false
}

func (d *Dialer) informDialerGroupUpdate(collection *collection) {
	// Inform DialerGroups to update state.
	// We use lock because AliveDialerSetSet is a reference of that in collection.
	d.collectionFineMu.Lock()
	for a := range collection.AliveDialerSetSet {
		a.NotifyLatencyChange(d, collection.Alive)
	}
	d.collectionFineMu.Unlock()
}

func (d *Dialer) ReportUnavailable(typ *NetworkType, err error) {
	collection := d.mustGetCollection(typ)
	d.logUnavailable(collection, typ, err)
	d.informDialerGroupUpdate(collection)
}

func (d *Dialer) Check(opts *CheckOption) (ok bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	start := time.Now()
	// Calc latency.
	collection := d.mustGetCollection(opts.networkType)
	ok, err = opts.CheckFunc(ctx, opts.networkType)
	if ok && err == nil {
		// Success: update latency and mark alive.
		latency := time.Since(start)

		// Use lock to protect all collection updates
		d.collectionFineMu.Lock()
		collection.Latencies10.AppendLatency(latency)
		avg, _ := collection.Latencies10.AvgLatency()
		collection.MovingAverage = (collection.MovingAverage + latency) / 2
		collection.Alive = true
		d.collectionFineMu.Unlock()

		d.Log.WithFields(logrus.Fields{
			"network": opts.networkType.String(),
			"node":    d.property.Name,
			"last":    latency.Truncate(time.Millisecond).String(),
			"avg_10":  avg.Truncate(time.Millisecond),
			"mov_avg": collection.MovingAverage.Truncate(time.Millisecond),
		}).Debugln("Connectivity Check")
		d.informDialerGroupUpdate(collection)
	} else if err != nil {
		// Failure: mark unavailable only if there's an actual error.
		d.logUnavailable(collection, opts.networkType, err)
		d.informDialerGroupUpdate(collection)
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
	defer resp.Body.Close()
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
