/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
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

// ErrNoApplicableIP is a sentinel error returned by CheckFunc when the health
// check target has no DNS record for the requested IP version (e.g. an IPv4-only
// node has no AAAA record). It is distinguished from a plain (false, nil) skip
// so that check() can mark the node unavailable for that network type instead
// of preserving the initial alive=true state and silently routing traffic to a
// dead path.
var ErrNoApplicableIP = stderrors.New("no applicable IP for this network type")

// errCheckOptionUnavailable is a sentinel error returned by CheckFunc when the
// check option itself cannot be built (e.g. the TCP check URL cannot be
// resolved via the system resolver, or the DNS check target failed to parse).
// Such failures are probe-infrastructure problems shared by every dialer of
// the generation, not evidence about any single node's health, so check()
// skips health-state punishment for them instead of flapping all nodes.
//
// Deliberate asymmetry with ErrNoApplicableIP: a check target without a record
// for this IP version is still per-node-path evidence (traffic on that family
// would hit the same wall), so it keeps punishing; a broken check option says
// nothing about any path and must not punish.
var errCheckOptionUnavailable = stderrors.New("check option unavailable")

// wrapCheckOptionError classifies a check-option build failure. The sentinel
// stays unexported because it is plumbing between CheckFunc closures and
// check(); callers outside the package have no way to produce it.
func wrapCheckOptionError(err error) error {
	return fmt.Errorf("%w: %v", errCheckOptionUnavailable, err)
}

// isLifecycleTeardownError reports whether err carries no evidence about node
// health because it was produced by dialer teardown.
//
// Cancellation-shaped errors are always teardown: the check ctx's explicit
// cancel() runs only after CheckFunc has returned, so mid-probe cancellation
// can only come from the parent dialer context (retirement/reload); a check
// deadline expiry instead surfaces as context.DeadlineExceeded, which this
// predicate does not match and which must be punished as a slow node.
//
// Closed-connection errors are teardown only when this dialer is actually
// being retired (d.ctx done). While the dialer is live, net.ErrClosed is NOT
// teardown: mux protocols in the outbound fork (anytls, juicity, ...) surface
// net.ErrClosed when the remote side kills the session, and that must still
// count as node evidence so the node can be punished.
//
// Note: an error that merely CONTAINS the text "context canceled" without
// chaining context.Canceled does not take the unconditional leg and is
// punished while the dialer is live. That narrowing is deliberate: every
// in-tree producer chains context.Canceled (or is gated on d.ctx), so a bare
// string match could only fire for foreign code, where erring toward node
// evidence is the safe direction.
func (d *Dialer) isLifecycleTeardownError(err error) bool {
	if !commonerrors.IsCanceledOrClosed(err) {
		return false
	}
	if stderrors.Is(err, context.Canceled) {
		return true
	}
	return d.ctx.Err() != nil
}

type UdpHealthDomain uint8

const (
	UdpHealthDomainUnset UdpHealthDomain = iota
	UdpHealthDomainDns
	UdpHealthDomainData
)

func (d UdpHealthDomain) String() string {
	switch d {
	case UdpHealthDomainDns:
		return "dns_udp"
	case UdpHealthDomainData:
		return "data_udp"
	default:
		return "udp"
	}
}

type NetworkType struct {
	L4Proto         consts.L4ProtoStr
	IpVersion       consts.IpVersionStr
	IsDns           bool
	UdpHealthDomain UdpHealthDomain
}

func (t *NetworkType) String() string {
	if t.IsDnsSemantic() {
		return t.StringWithoutDns() + "(DNS)"
	} else {
		return t.StringWithoutDns()
	}
}

func (t *NetworkType) StringWithoutDns() string {
	return string(t.L4Proto) + string(t.IpVersion)
}

func (t *NetworkType) EffectiveUdpHealthDomain() UdpHealthDomain {
	if t == nil || t.L4Proto != consts.L4ProtoStr_UDP {
		return UdpHealthDomainUnset
	}
	// UDP callers must set DNS explicitly via UdpHealthDomainDns. Unset falls
	// back only to the ordinary data-UDP domain.
	if t.UdpHealthDomain != UdpHealthDomainUnset {
		return t.UdpHealthDomain
	}
	return UdpHealthDomainData
}

func (t *NetworkType) IsDnsSemantic() bool {
	if t == nil {
		return false
	}
	if t.L4Proto == consts.L4ProtoStr_UDP {
		return t.EffectiveUdpHealthDomain() == UdpHealthDomainDns
	}
	return t.IsDns
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
// UDP health is split into two independent domains:
//  1. DNS UDP health, driven by DNS probes and DNS request failures.
//  2. Data UDP health, driven by real proxied UDP traffic and shared hard failures.
//
// This prevents transient DNS probe failures from directly poisoning long-lived
// data UDP traffic such as QUIC and games, while still allowing shared transport
// failures to fan out into both domains when appropriate.
func (t *NetworkType) Index() int {
	return t.HealthKey().CollectionIndex()
}

type collection struct {
	// AliveDialerSetSet uses reference counting.
	AliveDialerSetSet AliveDialerSetSet
	Latencies10       *LatenciesN
	MovingAverage     time.Duration
	LastProbe         DialerProbeObservationSnapshot
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

// dnsBorrowedLatencyV4/V6 are immutable singletons for the data-UDP latency
// borrow: allocating a fresh NetworkType per notification served nothing.
var (
	dnsBorrowedLatencyV4 = &NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		IsDns:           true,
		UdpHealthDomain: UdpHealthDomainDns,
	}
	dnsBorrowedLatencyV6 = &NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_6,
		IsDns:           true,
		UdpHealthDomain: UdpHealthDomainDns,
	}
)

func (d *Dialer) SnapshotLastProbe(typ *NetworkType) DialerProbeObservationSnapshot {
	if d == nil || typ == nil {
		return DialerProbeObservationSnapshot{}
	}
	d.collectionFineMu.RLock()
	defer d.collectionFineMu.RUnlock()
	collection := d.mustGetCollection(typ)
	if collection == nil {
		return DialerProbeObservationSnapshot{}
	}
	return collection.LastProbe
}

type collectionUpdate struct {
	alive             bool
	movingAverage     time.Duration
	aliveDialerGroups []*AliveDialerSet
	// borrowedGroups/borrowedAlive carry the data-UDP fan-out produced by a
	// DNS-UDP domain update. The data-UDP domain has no latency probe of its
	// own and borrows the DNS domain's latency (see
	// snapshotLatencyForPolicy), but its AliveDialerSets are only notified
	// while the domain itself is still dead (ReportAvailableTraffic gates on
	// !MustGetAlive) - so without this fan-out their borrowed sorting
	// latency freezes at the value captured on the revival.
	//
	// borrowedAlive is ALWAYS the data-UDP collection's own Alive.Load(), and
	// borrowedGroups is snapshotted under the same collectionFineMu critical
	// section as the update itself. Both notifications are delivered after
	// that lock is released (see informDialerGroupUpdate).
	borrowedGroups []*AliveDialerSet
	borrowedAlive  bool
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
	// Data-UDP has no latency probe of its own: real proxied UDP traffic only
	// flips the alive flag and never records a delay, so its collection always
	// reports hasLatency=false and node selection fell back to configuration
	// order / add_latency only (see daeuniverse/dae#1072).
	//
	// Reuse the DNS-UDP health domain of the same dialer as a proxy signal:
	// both domains traverse the very same upstream proxy channel (only the
	// final destination differs by a few ms), so the DNS-UDP probe delay
	// faithfully represents the channel quality seen by data-UDP. Only the
	// latency is borrowed; the data-UDP alive state remains driven exclusively
	// by real UDP traffic, preserving the deliberate isolation between the two
	// health domains.
	latencyType := typ
	if typ.L4Proto == consts.L4ProtoStr_UDP && typ.EffectiveUdpHealthDomain() == UdpHealthDomainData {
		switch typ.IpVersion {
		case consts.IpVersionStr_6:
			latencyType = dnsBorrowedLatencyV6
		default:
			latencyType = dnsBorrowedLatencyV4
		}
	}
	d.collectionFineMu.RLock()
	collection := d.mustGetCollection(latencyType)
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
		penalty := d.getBackoffPenaltyForType(typ)
		if latencyType != typ {
			// A borrowed latency inherits the DNS domain's backoff penalty as
			// well: when the DNS probe is failing, the channel is likely
			// degraded for data-UDP too, and the penalty compensates for the
			// otherwise stale success samples.
			penalty = max(penalty, d.getBackoffPenaltyForType(latencyType))
		}
		rawLatency += penalty
	}
	return rawLatency, hasLatency
}

func (d *Dialer) snapshotAliveDialerGroupsLocked(collection *collection) []*AliveDialerSet {
	if collection == nil || len(collection.AliveDialerSetSet) == 0 {
		return nil
	}
	groups := make([]*AliveDialerSet, 0, len(collection.AliveDialerSetSet))
	for a := range collection.AliveDialerSetSet {
		groups = append(groups, a)
	}
	return groups
}

// dataUdpBorrowerGroupsLocked resolves, for a DNS-UDP domain update, the
// same-ipversion data-UDP AliveDialerSets that borrow this domain's latency,
// together with the data-UDP domain's OWN alive state.
//
// Callers must hold collectionFineMu: the whole point is that the fan-out
// target set and its alive bit are snapshotted inside the very critical
// section that produced the update. It performs no notification and no I/O.
//
// Lock order: AliveDialerSet.mu -> collectionFineMu is the established order
// (NotifyLatencyChange holds the set lock while calling
// snapshotLatencyForPolicy). This helper is only ever called with
// collectionFineMu held and never takes a set lock, so the order is kept
// one-way here; the delivery happens after the unlock.
//
// ok is false when typ is not a DNS-UDP domain or the data-UDP domain has no
// registered sets, in which case the update has no borrowed fan-out.
func (d *Dialer) dataUdpBorrowerGroupsLocked(typ *NetworkType) (groups []*AliveDialerSet, alive bool, ok bool) {
	if typ == nil || typ.L4Proto != consts.L4ProtoStr_UDP ||
		typ.EffectiveUdpHealthDomain() != UdpHealthDomainDns {
		return nil, false, false
	}
	dataType := &NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       typ.IpVersion,
		UdpHealthDomain: UdpHealthDomainData,
	}
	collection := d.mustGetCollection(dataType)
	if collection == nil {
		return nil, false, false
	}
	groups = d.snapshotAliveDialerGroupsLocked(collection)
	if len(groups) == 0 {
		return nil, false, false
	}
	// The data-UDP alive flag must come from the data-UDP collection itself:
	// borrowing the DNS domain's value would flip data-UDP aliveness from a
	// DNS probe, which the health-domain split deliberately forbids.
	return groups, collection.Alive.Load(), true
}

// attachBorrowedUdpFanOutLocked fills update's borrowed fan-out fields.
// Callers must hold collectionFineMu.
func (d *Dialer) attachBorrowedUdpFanOutLocked(typ *NetworkType, update *collectionUpdate) {
	if update == nil {
		return
	}
	if groups, alive, ok := d.dataUdpBorrowerGroupsLocked(typ); ok {
		update.borrowedGroups = groups
		update.borrowedAlive = alive
	}
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

func parseTcpCheckOption(ctx context.Context, rawURL []string, method string, resolverNetwork string, directDialer netproxy.Dialer, systemDNSResolver SystemDNSResolver) (opt *TcpCheckOption, err error) {
	if directDialer == nil {
		directDialer = direct.SymmetricDirect
	}
	if method == "" {
		method = http.MethodGet
	}
	var systemDns netip.AddrPort
	if systemDNSResolver == nil {
		systemDns, err = netutils.SystemDns()
	} else {
		systemDns, err = systemDNSResolver.SystemDNS()
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if err == nil {
			return
		}
		if systemDNSResolver == nil {
			_ = netutils.TryUpdateSystemDnsElapse(time.Second)
		} else {
			_ = systemDNSResolver.TryUpdateElapse(time.Second)
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
		ip46, _, _ = netutils.ResolveIp46(ctx, directDialer, systemDns, u.Hostname(), resolverNetwork, false)
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

func parseCheckDNSOption(ctx context.Context, dnsHostPort []string, resolverNetwork string, directDialer netproxy.Dialer, systemDNSResolver SystemDNSResolver) (opt *CheckDnsOption, err error) {
	if directDialer == nil {
		directDialer = direct.SymmetricDirect
	}
	var systemDns netip.AddrPort
	if systemDNSResolver == nil {
		systemDns, err = netutils.SystemDns()
	} else {
		systemDns, err = systemDNSResolver.SystemDNS()
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if err == nil {
			return
		}
		if systemDNSResolver == nil {
			_ = netutils.TryUpdateSystemDnsElapse(time.Second)
		} else {
			_ = systemDNSResolver.TryUpdateElapse(time.Second)
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
		return nil, fmt.Errorf("bad port: %w", err)
	}
	var ip46 *netutils.Ip46
	if len(dnsHostPort) > 1 {
		ip46 = parseIp46FromList(dnsHostPort[1:])
	} else {
		ip46, _, _ = netutils.ResolveIp46(ctx, directDialer, systemDns, host, resolverNetwork, false)
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
	opt               *TcpCheckOption
	mu                sync.Mutex
	Log               *logrus.Logger
	Raw               []string
	ResolverNetwork   string
	Method            string
	DirectDialer      netproxy.Dialer
	SystemDNSResolver SystemDNSResolver
}

func (c *TcpCheckOptionRaw) Reset() {
	c.mu.Lock()
	c.opt = nil
	c.mu.Unlock()
}

func (c *TcpCheckOptionRaw) Option() (opt *TcpCheckOption, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		ctx, cancel := context.WithTimeout(context.Background(), Timeout)
		defer cancel()
		type contextKey string
		ctx = context.WithValue(ctx, contextKey("logger"), c.Log)
		tcpCheckOption, err := parseTcpCheckOption(ctx, c.Raw, c.Method, c.ResolverNetwork, c.DirectDialer, c.SystemDNSResolver)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tcp_check_url: %w", err)
		}
		c.opt = tcpCheckOption
	}
	return c.opt, nil
}

type CheckDnsOptionRaw struct {
	opt               *CheckDnsOption
	mu                sync.Mutex
	Raw               []string
	ResolverNetwork   string
	Somark            uint32
	DirectDialer      netproxy.Dialer
	SystemDNSResolver SystemDNSResolver
}

func (c *CheckDnsOptionRaw) Reset() {
	c.mu.Lock()
	c.opt = nil
	c.mu.Unlock()
}

func (c *CheckDnsOptionRaw) Option() (opt *CheckDnsOption, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		ctx, cancel := context.WithTimeout(context.Background(), Timeout)
		defer cancel()
		udpCheckOption, err := parseCheckDNSOption(ctx, c.Raw, c.ResolverNetwork, c.DirectDialer, c.SystemDNSResolver)
		if err != nil {
			return nil, fmt.Errorf("failed to parse udp_check_dns: %w", err)
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

func initialConnectivityCheckJitterWindow(cycle time.Duration, activeDialers int) time.Duration {
	coldStartWindow := time.Duration(activeDialers) * 50 * time.Millisecond
	if maxWindow := cycle / 4; maxWindow > 0 && coldStartWindow > maxWindow {
		coldStartWindow = maxWindow
	}
	if coldStartWindow < time.Second {
		coldStartWindow = time.Second
	}
	return coldStartWindow
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
		// Use nonblocking mode so reload/cancel paths never stall behind a
		// saturated health-check pool. Skipping a probe is preferable to
		// keeping an old dialer generation alive.
		p, err := ants.NewPool(size, ants.WithNonblocking(true))
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
	if cycle <= 0 {
		// The daemon config layer enforces a positive interval, but a
		// programmatic GlobalOption is unvalidated; a non-positive cycle
		// would panic in fastrand.Int63n below on the first check. Fall back
		// to the shortest sensible cadence instead of crashing.
		cycle = time.Second
	}
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
				return false, wrapCheckOptionError(err)
			}
			if !opt.Ip4.IsValid() {
				d.Log.WithFields(logrus.Fields{
					"link":    d.TcpCheckOptionRaw.Raw,
					"dialer":  d.property.Name,
					"network": typ.String(),
				}).Debugln("Skip check due to no DNS record.")
				return false, ErrNoApplicableIP
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
				return false, wrapCheckOptionError(err)
			}
			if !opt.Ip6.IsValid() {
				d.Log.WithFields(logrus.Fields{
					"link":    d.TcpCheckOptionRaw.Raw,
					"dialer":  d.property.Name,
					"network": typ.String(),
				}).Debugln("Skip check due to no DNS record.")
				return false, ErrNoApplicableIP
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
				return false, wrapCheckOptionError(err)
			}
			addr := ip(opt)
			if !addr.IsValid() {
				d.Log.WithFields(logrus.Fields{
					"link":    d.CheckDnsOptionRaw.Raw,
					"network": typ.String(),
				}).Debugln("Skip check due to no DNS record.")
				return false, ErrNoApplicableIP
			}
			return d.DnsCheck(ctx, netip.AddrPortFrom(addr, opt.DnsPort), *network)
		}
	}

	udp4CheckDnsOpt := &CheckOption{
		networkType: &NetworkType{
			L4Proto:         consts.L4ProtoStr_UDP,
			IpVersion:       consts.IpVersionStr_4,
			IsDns:           true,
			UdpHealthDomain: UdpHealthDomainDns,
		},
		CheckFunc: makeDnsCheckFunc(func(o *CheckDnsOption) netip.Addr { return o.Ip4 }, &udpNetwork),
	}
	udp6CheckDnsOpt := &CheckOption{
		networkType: &NetworkType{
			L4Proto:         consts.L4ProtoStr_UDP,
			IpVersion:       consts.IpVersionStr_6,
			IsDns:           true,
			UdpHealthDomain: UdpHealthDomainDns,
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
	coldStartWindow := initialConnectivityCheckJitterWindow(cycle, getActiveDialerCount())
	initialDelay := time.Duration(fastrand.Int63n(int64(coldStartWindow)))
	if d.reloadInheritedHealth.Swap(false) && cycle > 0 {
		initialDelay += cycle
	}
	d.tickerMu.Lock()
	d.ticker = time.NewTimer(initialDelay)
	// A Timer's channel never changes across Reset, so capturing it once keeps
	// the select below off d.ticker, which RetireForEstablishedFlows clears
	// concurrently when a reload retires this dialer.
	tickerC := d.ticker.C
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

	// Pool pointer is stable (Tune never replaces it); capture once.
	workerPool := getConnectivityCheckPool()
	isFirstCheck := true

	for {
		// Check if the dialer is still useful. If not, exit the goroutine.
		if checkUnused() {
			return
		}

		// checkFamily is non-empty when triggered by NotifyCheckDnsUdp/NotifyCheckTcp:
		// only the matching check opts are run (both IPv4 and IPv6), and the
		// periodic ticker is left untouched so the regular schedule is not disrupted.
		var checkFamily consts.L4ProtoStr
		var cycleRes *cycleResult
		select {
		case <-d.ctx.Done():
			return
		case <-tickerC:
		case <-d.checkCh:
		case <-d.checkDnsUdpCh:
			checkFamily = consts.L4ProtoStr_UDP
		case <-d.checkTcpCh:
			checkFamily = consts.L4ProtoStr_TCP
		}

		d.TcpCheckOptionRaw.Reset()
		d.CheckDnsOptionRaw.Reset()

		opts := CheckOpts
		if checkFamily != "" {
			// Targeted check: run all checks matching the triggered protocol family (v4 + v6).
			opts = filterCheckOptsByFamily(CheckOpts, checkFamily)
		} else {
			// Full check: advance the sticky IP cache cycle to allow IP failover.
			d.IncrementCheckCycle()
			cycleRes = &cycleResult{}
		}

		var wg sync.WaitGroup
		d.submitCheckTasks(workerPool, &wg, opts, checkFamily != "", cycleRes)
		// Per-cycle waiter goroutine evaluated (round 11) and kept: it runs
		// microseconds per interval across all dialers; alternatives either
		// spin or complicate submit/failure accounting.
		waitDone := make(chan struct{})
		go func() {
			wg.Wait()
			close(waitDone)
		}()
		select {
		case <-waitDone:
		case <-d.ctx.Done():
			return
		}
		if checkFamily == "" {
			// Stability-based wash white: only reset stability if a protocol family had failures
			// WITHOUT any successes in this cycle. This allows partially-working dual-stack
			// nodes (e.g. V4 OK, V6 broken) to eventually wash white their penalty.
			d.NotifyPeriodicCheckResult(consts.L4ProtoStr_TCP, cycleRes.tcpSuccess, cycleRes.tcpFailure && !cycleRes.tcpSuccess)
			d.NotifyPeriodicCheckResultForType(udp4CheckDnsOpt.networkType, cycleRes.udpSuccess, cycleRes.udpFailure && !cycleRes.udpSuccess)
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
// the given proto family.
func filterCheckOptsByFamily(opts []*CheckOption, family consts.L4ProtoStr) []*CheckOption {
	var result []*CheckOption
	for _, opt := range opts {
		if opt.networkType.L4Proto == family {
			result = append(result, opt)
		}
	}
	return result
}

// submitCheckTasks submits check tasks to worker pool.
func (d *Dialer) submitCheckTasks(workerPool *ants.Pool, wg *sync.WaitGroup, opts []*CheckOption, isResuscitation bool, cycle *cycleResult) {
	for _, opt := range opts {
		// No need to test if there is no dialer selection policy using its latency.
		if !d.hasAliveDialerSets(opt.networkType) {
			continue
		}

		select {
		case <-d.ctx.Done():
			return
		default:
		}

		wg.Add(1)
		checkOpt := opt
		worker := func() {
			defer wg.Done()
			select {
			case <-d.ctx.Done():
				return
			default:
			}
			_, _ = d.check(checkOpt, isResuscitation, cycle)
		}
		submitNow := func() {
			// wg ownership: the worker Dones on completion; callers of
			// submitNow must Done only when the worker never runs.
			if err := workerPool.Submit(worker); err != nil {
				// Nonblocking pools report overload immediately. Health checks are
				// periodic, so skip this probe instead of spawning an unbounded
				// goroutine that can outlive the dialer lifecycle.
				wg.Done()
			}
		}

		if isResuscitation {
			// Stagger resuscitation probes to prevent thundering herd: a
			// random delay between 0 and 2 seconds. The wait must happen
			// OUTSIDE the worker pool — sleeping inside pool workers makes
			// each emergency probe occupy a pool slot for the whole delay and,
			// during a fleet-wide outage (every node resuscitating at once),
			// starves the periodic checks of healthy nodes exactly when they
			// matter most.
			time.AfterFunc(time.Duration(fastrand.Int63n(int64(2*time.Second))), func() {
				select {
				case <-d.ctx.Done():
					// Retired while waiting for the stagger: drop the task.
					wg.Done()
					return
				default:
				}
				submitNow()
			})
			continue
		}
		submitNow()
	}
}

// NotifyCheck will succeed only when CheckEnabled is true.
func (d *Dialer) NotifyCheck() {
	select {
	case <-d.ctx.Done():
		return
	default:
	}

	// 2s cooldown, mirroring NotifyCheckDnsUdp/NotifyCheckTcp: NotifyCheck is
	// reachable from the exported TriggerLatencyChecks API, and a fast GUI
	// poller could otherwise drive back-to-back full checks (each occupying
	// worker-pool slots and re-resolving the check URL).
	now := time.Now().UnixNano()
	pre := d.lastNotifyCheck.Load()
	if now-pre < int64(2*time.Second) {
		return
	}
	if !d.lastNotifyCheck.CompareAndSwap(pre, now) {
		return
	}

	select {
	// If fail to push elem to chan, the check is in process.
	case d.checkCh <- time.Now():
	default:
	}
}

// NotifyCheckDnsUdp triggers a targeted DNS-UDP health check for both IPv4 and IPv6.
func (d *Dialer) NotifyCheckDnsUdp() {
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
	case d.checkDnsUdpCh <- struct{}{}:
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
			// EADDRNOTAVAIL means no usable source address of this family on
			// the host, not that the family is unsupported per se.
			err = fmt.Errorf("no usable IPv%v source address", network.IpVersion)
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
	if !force && proxyFailureSuppressedForReload() {
		update := collectionUpdate{
			alive:         collection.Alive.Load(),
			movingAverage: collection.MovingAverage,
		}
		d.collectionFineMu.Unlock()
		if d.Log != nil && d.Log.IsLevelEnabled(logrus.DebugLevel) {
			nodeName := ""
			if d.property != nil {
				nodeName = d.property.Name
			}
			d.Log.WithFields(logrus.Fields{
				"network": typ.String(),
				"node":    nodeName,
			}).Debugln("Suppressing dialer availability failure during reload handoff")
		}
		return update
	}
	// UDP/TCP robustness: only mark unavailable after consecutive failures.
	// This protects against transient network interference.
	threshold := 1
	switch typ.L4Proto {
	case consts.L4ProtoStr_UDP:
		if isTraffic {
			// Higher threshold for data traffic to avoid flipping during transient jitter.
			threshold = 50
		} else {
			// UDP health checks use DNS queries which are more susceptible to
			// transient packet loss than TCP HTTP checks. A single dropped DNS
			// response should not tear down all established UDP endpoints (game
			// sessions, QUIC connections, etc.). Require 3 consecutive failures
			// before declaring the dialer dead for UDP.
			threshold = 3
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
	d.attachBorrowedUdpFanOutLocked(typ, &update)
	d.collectionFineMu.Unlock()

	if wasAlive != alive {
		d.notifyAliveTransition(typ, alive)
	}

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
	d.attachBorrowedUdpFanOutLocked(typ, &update)
	d.collectionFineMu.Unlock()

	// Notify about health check success.
	// isRevival is true if we were dead.
	// We no longer trigger recovery detection for explicit resuscitation probes on already-alive nodes
	// to prevent "self-punishment" (unnecessary level increments).
	isRevival := !wasAlive
	d.NotifyHealthCheckResult(typ, true, isRevival)
	if isRevival {
		d.notifyAliveTransition(typ, true)
	}

	return update, avg
}

func (d *Dialer) markAvailableTraffic(typ *NetworkType) collectionUpdate {
	d.collectionFineMu.Lock()
	idx := typ.Index()
	collection := d.collections[idx]

	d.failCount[idx] = 0
	d.trafficFailCount[idx].Store(0)
	wasAlive := collection.Alive.Swap(true)
	update := collectionUpdate{
		alive:             true,
		movingAverage:     collection.MovingAverage,
		aliveDialerGroups: d.snapshotAliveDialerGroupsLocked(collection),
	}
	d.attachBorrowedUdpFanOutLocked(typ, &update)
	d.collectionFineMu.Unlock()

	isRevival := !wasAlive
	d.NotifyHealthCheckResult(typ, true, isRevival)
	if isRevival {
		d.notifyAliveTransition(typ, true)
	}
	return update
}

func (d *Dialer) informDialerGroupUpdate(update collectionUpdate) {
	for _, a := range update.aliveDialerGroups {
		a.NotifyLatencyChange(d, update.alive)
	}
	// Borrowed fan-out (data-UDP domains of the same ipversion). Delivered
	// here, i.e. strictly AFTER collectionFineMu was released: the
	// established lock order is AliveDialerSet.mu -> collectionFineMu
	// (NotifyLatencyChange holds the set lock while snapshotLatencyForPolicy
	// takes the collection lock), so notifying inside the critical section
	// that produced the snapshot would invert the order and deadlock.
	for _, a := range update.borrowedGroups {
		a.NotifyLatencyChange(d, update.borrowedAlive)
	}
}

func (d *Dialer) shouldIgnoreAvailabilityError(typ *NetworkType, err error) bool {
	if !commonerrors.IsCanceledOrClosed(err) {
		return false
	}
	if d != nil && d.Log != nil && d.Log.IsLevelEnabled(logrus.DebugLevel) {
		nodeName := ""
		networkName := ""
		if d.property != nil {
			nodeName = d.property.Name
		}
		if typ != nil {
			networkName = typ.String()
		}
		d.Log.WithFields(logrus.Fields{
			"network": networkName,
			"node":    nodeName,
			"err":     err.Error(),
		}).Debugln("Ignoring teardown-related dialer failure")
	}
	return true
}

func (d *Dialer) ReportUnavailable(typ *NetworkType, err error) {
	if d.shouldIgnoreAvailabilityError(typ, err) {
		return
	}
	d.logUnavailable(typ, err)
	d.informDialerGroupUpdate(d.markUnavailableInternal(typ, false, true))
}

func (d *Dialer) ReportUnavailableTransactional(typ *NetworkType, err error) {
	if d.shouldIgnoreAvailabilityError(typ, err) {
		return
	}
	d.logUnavailable(typ, err)
	d.informDialerGroupUpdate(d.markUnavailableInternal(typ, false, false))
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
	if typ.L4Proto == consts.L4ProtoStr_UDP && typ.EffectiveUdpHealthDomain() == UdpHealthDomainData && !d.MustGetAlive(typ) {
		d.informDialerGroupUpdate(d.markAvailableTraffic(typ))
	}
}

// check performs a basic connectivity check for one dialer.
func (d *Dialer) check(opts *CheckOption, isResuscitation bool, cycle *cycleResult) (ok bool, err error) {
	const maxAttempts = 2
	var bestLatency time.Duration
	checkedAt := time.Now()

	for range maxAttempts {
		ctx, cancel := context.WithTimeout(d.ctx, Timeout)
		start := time.Now()
		ok, err = opts.CheckFunc(ctx, opts.networkType)
		latency := time.Since(start)
		checkedAt = time.Now()
		cancel()

		if ok && err == nil {
			bestLatency = latency
			break
		}
		if stderrors.Is(err, context.Canceled) {
			break
		}
		if err == nil || stderrors.Is(err, ErrNoApplicableIP) || stderrors.Is(err, errCheckOptionUnavailable) {
			// No applicable IP, a plain skip, or a probe-infrastructure
			// failure (check option cannot be built); don't retry — the DNS
			// record or the option will not change between two attempts
			// within the same check cycle.
			break
		}
		// Retry on actual error.
	}
	switch {
	case ok && err == nil:
		d.collectionFineMu.Lock()
		collection := d.mustGetCollection(opts.networkType)
		collection.LastProbe = DialerProbeObservationSnapshot{
			CheckedAt:  checkedAt,
			Alive:      true,
			Latency:    bestLatency,
			HasLatency: true,
			Message:    FormatLatencyMessage(&LatencyProbeResult{Alive: true, Latency: bestLatency}),
		}
		d.collectionFineMu.Unlock()

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
	case err != nil && !d.isLifecycleTeardownError(err) && !stderrors.Is(err, errCheckOptionUnavailable):
		d.collectionFineMu.Lock()
		collection := d.mustGetCollection(opts.networkType)
		collection.LastProbe = DialerProbeObservationSnapshot{
			CheckedAt: checkedAt,
			Alive:     false,
			Message:   err.Error(),
		}
		d.collectionFineMu.Unlock()

		// Failure: mark unavailable only if there's an actual error. Teardown
		// errors racing dialer retirement and probe-infrastructure failures
		// carry no evidence about node health and must not poison dialer
		// state or the process-global proxy failure tracker.
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
	case stderrors.Is(err, errCheckOptionUnavailable):
		// Probe-infrastructure failure: health state is preserved. Warn at a
		// limited rate so a persistent misconfiguration (e.g. an unresolvable
		// tcp_check_url) stays observable instead of silently keeping every
		// node at its initial alive state.
		now := time.Now().UnixNano()
		if pre := d.lastCheckOptionWarn.Load(); now-pre > int64(time.Minute) {
			if d.lastCheckOptionWarn.CompareAndSwap(pre, now) {
				d.Log.WithFields(logrus.Fields{
					"network": opts.networkType.String(),
					"node":    d.property.Name,
				}).Warnf("Connectivity check option unavailable; node health state preserved: %v", err)
			}
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
		if netErr, ok := stderrors.AsType[net.Error](err); ok && netErr.Timeout() {
			err = fmt.Errorf("timeout")
		}
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Judge the status code.
	if page := path.Base(req.URL.Path); strings.HasPrefix(page, "generate_") {
		if strconv.Itoa(resp.StatusCode) != strings.TrimPrefix(page, "generate_") {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
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
