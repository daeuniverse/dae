/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package stickyip provides sticky IP caching for proxy server connections.
// Within a health check cycle, the same resolved IP is reused to ensure
// connection stability when a proxy domain resolves to multiple IPs.
package stickyip

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

const (
	// CacheTTL is how long to cache a successful proxy IP.
	// This should be at least the health check interval to ensure
	// all connections in a cycle use the same IP.
	CacheTTL = 5 * time.Minute
)

// ProxyIpCache manages sticky IP resolution for proxy server domains.
// It separately caches IPs that work for TCP and UDP since some proxies
// may have different availability per protocol.
type ProxyIpCache struct {
	sync.RWMutex
	cache map[string]*proxyIpEntry
}

type proxyIpEntry struct {
	// tcp4Addr is the IPv4:port that works for TCP connections.
	tcp4Addr string
	// tcp6Addr is the IPv6:port that works for TCP connections.
	tcp6Addr string
	// udp4Addr is the IPv4:port that works for UDP connections.
	udp4Addr string
	// udp6Addr is the IPv6:port that works for UDP connections.
	udp6Addr string
	// expiresAt is when this cache entry expires.
	expiresAt time.Time
	// checkCycle is the health check cycle number this entry belongs to.
	checkCycle uint64
}

// cacheKey generates a cache key from network (tcp/udp) and IP version (4/6).
func cacheKey(network, ipVersion string) string {
	return network + ipVersion
}

// NewProxyIpCache creates a new proxy IP cache.
func NewProxyIpCache() *ProxyIpCache {
	return &ProxyIpCache{
		cache: make(map[string]*proxyIpEntry),
	}
}

// Set stores a successful proxy IP address for a specific protocol and IP version with cycle tracking.
// network should be "tcp" or "udp", ipVersion should be "4" or "6".
// This ensures we only cache IPs that actually work for the specific protocol and address family.
func (c *ProxyIpCache) Set(originalAddr, actualAddr string, network string, ipVersion string, cycle uint64) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	now := time.Now()

	// Get or create entry
	entry, exists := c.cache[originalAddr]
	if !exists {
		entry = &proxyIpEntry{
			expiresAt:  now.Add(CacheTTL),
			checkCycle: cycle,
		}
		c.cache[originalAddr] = entry
	}

	// Update the appropriate address based on network type and IP version
	key := cacheKey(network, ipVersion)
	switch key {
	case "tcp4":
		entry.tcp4Addr = actualAddr
	case "tcp6":
		entry.tcp6Addr = actualAddr
	case "udp4":
		entry.udp4Addr = actualAddr
	case "udp6":
		entry.udp6Addr = actualAddr
	}

	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"original_addr": originalAddr,
			"actual_addr":   actualAddr,
			"network":       network,
			"ip_version":    ipVersion,
			"cycle":         cycle,
		}).Debug("[StickyIP] Cached proxy IP")
	}
}

// GetWithCycleAndIpVersion returns the cached IP for the specified network and IP version if it belongs to the current check cycle.
// network should be "tcp" or "udp", ipVersion should be "4" or "6".
func (c *ProxyIpCache) GetWithCycleAndIpVersion(proxyAddr string, network string, ipVersion string, currentCycle uint64) string {
	if c == nil {
		logger.WithField("proxy_addr", proxyAddr).Debug("[StickyIP] Cache is nil")
		return proxyAddr
	}
	c.RLock()
	defer c.RUnlock()
	entry, ok := c.cache[proxyAddr]
	if !ok {
		logger.WithField("proxy_addr", proxyAddr).Debug("[StickyIP] No cache entry found")
		return proxyAddr
	}
	if time.Now().After(entry.expiresAt) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"expired_at": entry.expiresAt,
		}).Debug("[StickyIP] Cache entry expired")
		return proxyAddr
	}
	// Only use cached IP if it's from the current cycle
	if entry.checkCycle != currentCycle {
		logger.WithFields(logrus.Fields{
			"proxy_addr":    proxyAddr,
			"entry_cycle":   entry.checkCycle,
			"current_cycle": currentCycle,
		}).Debug("[StickyIP] Cycle mismatch - cache not from current cycle")
		return proxyAddr
	}

	// Return the protocol and IP version specific cached address
	var cachedAddr string
	key := cacheKey(network, ipVersion)
	switch key {
	case "tcp4":
		cachedAddr = entry.tcp4Addr
	case "tcp6":
		cachedAddr = entry.tcp6Addr
	case "udp4":
		cachedAddr = entry.udp4Addr
	case "udp6":
		cachedAddr = entry.udp6Addr
	}

	if cachedAddr == "" {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"network":    network,
			"ip_version": ipVersion,
		}).Debug("[StickyIP] No cached IP for this network type and IP version")
		return proxyAddr
	}

	logger.WithFields(logrus.Fields{
		"proxy_addr":  proxyAddr,
		"cached_addr": cachedAddr,
		"network":     network,
		"ip_version":  ipVersion,
	}).Debug("[StickyIP] Cache hit - returning cached IP")
	return cachedAddr
}

// GetWithCycle returns the cached IP for the specified network (backward compatibility).
// Deprecated: Use GetWithCycleAndIpVersion for proper IP version separation.
func (c *ProxyIpCache) GetWithCycle(proxyAddr string, network string, currentCycle uint64) string {
	// Try IPv4 first, then IPv6 for backward compatibility
	if addr := c.GetWithCycleAndIpVersion(proxyAddr, network, "4", currentCycle); addr != proxyAddr {
		return addr
	}
	return c.GetWithCycleAndIpVersion(proxyAddr, network, "6", currentCycle)
}

// Invalidate removes all cached entries for a proxy address.
func (c *ProxyIpCache) Invalidate(proxyAddr string) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	delete(c.cache, proxyAddr)
}

// InvalidateProtocolAndIpVersion removes the cached entry for a specific protocol and IP version.
// This allows fine-grained invalidation when a specific protocol + address family combination fails.
func (c *ProxyIpCache) InvalidateProtocolAndIpVersion(proxyAddr, network, ipVersion string) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	entry, exists := c.cache[proxyAddr]
	if !exists {
		return
	}

	key := cacheKey(network, ipVersion)
	switch key {
	case "tcp4":
		entry.tcp4Addr = ""
	case "tcp6":
		entry.tcp6Addr = ""
	case "udp4":
		entry.udp4Addr = ""
	case "udp6":
		entry.udp6Addr = ""
	}

	// If all addresses are empty now, remove the entry entirely
	if entry.tcp4Addr == "" && entry.tcp6Addr == "" && entry.udp4Addr == "" && entry.udp6Addr == "" {
		delete(c.cache, proxyAddr)
	} else {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"network":    network,
			"ip_version": ipVersion,
		}).Debug("[StickyIP] Invalidated cache for protocol+IP version")
	}
}

// InvalidateProtocol removes the cached entries for a specific protocol (both IPv4 and IPv6).
// This is kept for backward compatibility but invalidates both IP versions.
func (c *ProxyIpCache) InvalidateProtocol(proxyAddr, network string) {
	c.InvalidateProtocolAndIpVersion(proxyAddr, network, "4")
	c.InvalidateProtocolAndIpVersion(proxyAddr, network, "6")
}

// InvalidateCycle removes all cache entries for a specific cycle.
func (c *ProxyIpCache) InvalidateCycle(cycle uint64) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	for addr, entry := range c.cache {
		if entry.checkCycle == cycle {
			delete(c.cache, addr)
		}
	}
}

// StickyIpDialer wraps a dialer to provide sticky IP caching for proxy servers.
type StickyIpDialer struct {
	dialer     netproxy.Dialer
	cache      *ProxyIpCache
	checkCycle atomic.Uint64
	proxyAddr  string // Original proxy address (domain:port, IP:port, or port-union variant)
	proxyHost  string
	proxyPort  string
}

type ipLookupDialer interface {
	LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error)
}

// NewStickyIpDialer creates a new sticky IP dialer wrapper.
func NewStickyIpDialer(dialer netproxy.Dialer, proxyAddr string, cache *ProxyIpCache) *StickyIpDialer {
	if cache == nil {
		cache = NewProxyIpCache()
	}
	proxyHost, proxyPort, _ := SplitHostPort(proxyAddr)
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithField("proxy_addr", proxyAddr).Debug("[StickyIP] NewStickyIpDialer created")
	}
	return &StickyIpDialer{
		dialer:    dialer,
		cache:     cache,
		proxyAddr: proxyAddr,
		proxyHost: proxyHost,
		proxyPort: proxyPort,
	}
}

// IncrementCheckCycle advances the health check cycle.
func (d *StickyIpDialer) IncrementCheckCycle() {
	oldCycle := d.checkCycle.Load()
	newCycle := d.checkCycle.Add(1)
	logger.WithFields(logrus.Fields{
		"old_cycle":  oldCycle,
		"new_cycle":  newCycle,
		"proxy_addr": d.proxyAddr,
	}).Debug("[StickyIP] Check cycle incremented")
	// Invalidate old cycle entries to force refresh
	if newCycle > 0 {
		d.cache.InvalidateCycle(newCycle - 1)
	}
}

// InvalidateProtocolCache invalidates the cached IP for a specific protocol.
// This is called when a connection fails (e.g., connection refused) to allow
// immediate retry with a different IP.
func (d *StickyIpDialer) InvalidateProtocolCache(proxyAddr, protocol string) {
	d.cache.InvalidateProtocol(proxyAddr, protocol)
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"protocol":   protocol,
		}).Debug("[StickyIP] Protocol cache invalidated due to connection failure")
	}
}

// InvalidateProtocolAndIpVersionCache invalidates the cached IP for a specific protocol and IP version.
// This provides fine-grained cache invalidation when a specific combination fails.
func (d *StickyIpDialer) InvalidateProtocolAndIpVersionCache(proxyAddr, protocol, ipVersion string) {
	d.cache.InvalidateProtocolAndIpVersion(proxyAddr, protocol, ipVersion)
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"protocol":   protocol,
			"ip_version": ipVersion,
		}).Debug("[StickyIP] Protocol+IP version cache invalidated due to connection failure")
	}
}

// GetCachedProxyAddr returns the cached IP for the proxy address and network type.
// network should be "tcp" or "udp".
func (d *StickyIpDialer) GetCachedProxyAddr(network string) string {
	if d == nil {
		return ""
	}
	return d.cache.GetWithCycle(d.proxyAddr, network, d.checkCycle.Load())
}

// GetCachedProxyAddrWithIpVersion returns the cached IP for the proxy address, network type and IP version.
// network should be "tcp" or "udp", ipVersion should be "4" or "6".
func (d *StickyIpDialer) GetCachedProxyAddrWithIpVersion(network, ipVersion string) string {
	if d == nil {
		return ""
	}
	return d.cache.GetWithCycleAndIpVersion(d.proxyAddr, network, ipVersion, d.checkCycle.Load())
}

// DialContext implements sticky IP caching by intercepting dial calls.
// It resolves all IPs for the target, tries the cached IP first, then falls back.
func (d *StickyIpDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	// Extract the base network type (tcp/udp) and requested IP family from magic network if present.
	baseNetwork, requestedIPVersion := d.getNetworkPreference(network)

	// Log every dial attempt for debugging
	logger.WithFields(logrus.Fields{
		"proxy_addr":   d.proxyAddr,
		"target":       addr,
		"network":      network,
		"base_network": baseNetwork,
		"ip_version":   requestedIPVersion,
		"is_proxy":     d.isProxyAddress(addr),
	}).Debug("[StickyIP] DialContext called")

	// Check if we should use a cached proxy IP for this connection
	if d.isProxyAddress(addr) {
		cachedAddr := d.GetCachedProxyAddr(baseNetwork)
		if requestedIPVersion != "" {
			cachedAddr = d.GetCachedProxyAddrWithIpVersion(baseNetwork, requestedIPVersion)
		}
		// Only use cached IP if it's different from proxy address (i.e., it's a resolved IP)
		// GetCachedProxyAddr returns proxyAddr when cache is empty/expired, so we need to check
		if cachedAddr != "" && cachedAddr != d.proxyAddr {
			targetAddr := rewriteAddrPort(cachedAddr, addr)
			// Try with cached IP first
			conn, err := d.dialer.DialContext(ctx, network, targetAddr)
			if err == nil {
				logCacheHit(d.proxyAddr, targetAddr, network)
				return conn, nil
			} else {
				// Log cache miss/failure
				logCacheFailure(d.proxyAddr, targetAddr, network, err)
				// Cached IP failed, invalidate this protocol's cache
				d.cache.InvalidateProtocol(d.proxyAddr, baseNetwork)
			}
		}
		// No cached IP, or cached IP failed - resolve and try all IPs
		logger.WithFields(logrus.Fields{
			"proxy_addr":  d.proxyAddr,
			"target":      addr,
			"network":     network,
			"cached_addr": cachedAddr,
		}).Debug("[StickyIP] No valid cached IP - resolving proxy domain")
		return d.dialWithIpResolution(ctx, network, addr, baseNetwork, requestedIPVersion)
	}

	// Not the proxy address, just pass through
	logger.WithFields(logrus.Fields{
		"proxy_addr": d.proxyAddr,
		"target":     addr,
		"network":    network,
	}).Trace("[StickyIP] Pass-through (not proxy address)")
	return d.dialer.DialContext(ctx, network, addr)
}

// getNetworkPreference extracts the base network type (tcp/udp) and requested IP family from magic network.
func (d *StickyIpDialer) getNetworkPreference(network string) (baseNetwork string, ipVersion string) {
	// Parse magic network to get base type
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		// Default to treating as-is
		return network, ""
	}
	return magicNetwork.Network, magicNetwork.IPVersion
}

func (d *StickyIpDialer) lookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	if resolver, ok := d.dialer.(ipLookupDialer); ok {
		return resolver.LookupIPAddr(ctx, network, host)
	}
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// isProxyAddress checks if the given address matches the proxy address.
func (d *StickyIpDialer) isProxyAddress(addr string) bool {
	addrHost, addrPort, err := SplitHostPort(addr)
	if err != nil {
		return addr == d.proxyAddr
	}
	if addrHost != d.proxyHost {
		return false
	}
	return matchPortSpec(addrPort, d.proxyPort)
}

func matchPortSpec(port, spec string) bool {
	if port == spec || spec == "" {
		return true
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == port {
			return true
		}
		startStr, endStr, ok := strings.Cut(part, "-")
		if !ok {
			continue
		}
		start, errStart := strconv.Atoi(strings.TrimSpace(startStr))
		end, errEnd := strconv.Atoi(strings.TrimSpace(endStr))
		target, errTarget := strconv.Atoi(port)
		if errStart != nil || errEnd != nil || errTarget != nil {
			continue
		}
		if target >= start && target <= end {
			return true
		}
	}
	return false
}

// dialWithIpResolution resolves the address to IPs and tries each one.
// The first successful IP is cached for subsequent connections.
func (d *StickyIpDialer) dialWithIpResolution(ctx context.Context, network, addr, baseNetwork, requestedIPVersion string) (netproxy.Conn, error) {
	host, port, err := SplitHostPort(addr)
	if err != nil {
		// Not in host:port format, try directly
		logResolutionError(d.proxyAddr, "invalid address format", err)
		return d.dialer.DialContext(ctx, network, addr)
	}

	// If already an IP address, dial directly
	if ip := net.ParseIP(host); ip != nil {
		logDirectDial(d.proxyAddr, addr, network)
		return d.dialer.DialContext(ctx, network, addr)
	}

	// Resolve to get all IPs
	ips, err := d.lookupIPAddr(ctx, network, host)
	if err != nil || len(ips) == 0 {
		// Resolution failed, try original address
		logResolutionError(d.proxyAddr, host, err)
		return d.dialer.DialContext(ctx, network, addr)
	}
	ips = filterIPAddrsByVersion(ips, requestedIPVersion)
	if len(ips) == 0 {
		return nil, fmt.Errorf("no usable proxy IPs for %s%s", baseNetwork, requestedIPVersion)
	}

	// Log all resolved IPs
	logResolvedIPs(d.proxyAddr, ips, port, network)

	// Try each IP until one works
	var lastErr error
	for _, ipAddr := range ips {
		if ipAddr.IP == nil {
			continue
		}
		ipAddrStr := ipAddr.IP.String()
		targetAddr := net.JoinHostPort(ipAddrStr, port)

		logTryingIP(d.proxyAddr, targetAddr, network)
		conn, err := d.dialer.DialContext(ctx, network, targetAddr)
		if err == nil {
			// This IP works for this protocol, cache it
			// Determine IP version from the successful IP
			ipVersion := "4"
			if ipAddr.IP.To4() == nil {
				ipVersion = "6"
			}
			cycle := d.checkCycle.Load()
			d.cache.Set(d.proxyAddr, targetAddr, baseNetwork, ipVersion, cycle)
			logIPSuccess(d.proxyAddr, targetAddr, baseNetwork, ipVersion, cycle)
			return conn, nil
		}
		lastErr = err
		logIPFailure(d.proxyAddr, targetAddr, err)
	}

	// All IPs failed, return an error
	if lastErr == nil {
		lastErr = errNoUsableProxyIPs
	}
	logAllIPsFailed(d.proxyAddr, lastErr)
	return nil, &net.OpError{Op: "dial", Err: lastErr}
}

func filterIPAddrsByVersion(ips []net.IPAddr, ipVersion string) []net.IPAddr {
	if ipVersion == "" {
		return ips
	}
	filtered := make([]net.IPAddr, 0, len(ips))
	for _, ipAddr := range ips {
		switch ipVersion {
		case "4":
			if ipAddr.IP.To4() != nil {
				filtered = append(filtered, ipAddr)
			}
		case "6":
			if ipAddr.IP.To4() == nil {
				filtered = append(filtered, ipAddr)
			}
		}
	}
	return filtered
}

// SplitHostPort splits host:port strings and also accepts proxy port-union strings like
// example.com:443,8443-8450. IPv6 literals must use brackets, e.g. [2001:db8::1]:443.
func SplitHostPort(addr string) (host, port string, err error) {
	if strings.HasPrefix(addr, "[") {
		end := strings.LastIndexByte(addr, ']')
		if end == -1 || end+1 >= len(addr) || addr[end+1] != ':' {
			return "", "", &net.AddrError{Err: "missing port in address", Addr: addr}
		}
		host = addr[1:end]
		port = addr[end+2:]
		if port == "" {
			return "", "", &net.AddrError{Err: "missing port in address", Addr: addr}
		}
		return host, port, nil
	}

	colon := strings.LastIndexByte(addr, ':')
	if colon == -1 || colon == len(addr)-1 {
		return "", "", &net.AddrError{Err: "missing port in address", Addr: addr}
	}
	return addr[:colon], addr[colon+1:], nil
}

func rewriteAddrPort(cachedAddr, targetAddr string) string {
	cachedHost, _, err := SplitHostPort(cachedAddr)
	if err != nil {
		return cachedAddr
	}
	_, targetPort, err := SplitHostPort(targetAddr)
	if err != nil {
		return cachedAddr
	}
	return net.JoinHostPort(cachedHost, targetPort)
}

// Logging functions for debugging sticky IP caching

var logger = logrus.StandardLogger()

var errNoUsableProxyIPs = stderrors.New("no usable proxy IP addresses")

func logCacheHit(proxyAddr, cachedAddr, network string) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"cached_ip":  cachedAddr,
			"network":    network,
		}).Debug("[StickyIP] Cache hit - using cached proxy IP")
	}
}

func logCacheFailure(proxyAddr, cachedAddr, network string, err error) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"cached_ip":  cachedAddr,
			"network":    network,
			"error":      err.Error(),
		}).Debug("[StickyIP] Cached IP failed - invalidating and re-resolving")
	}
}

func logResolutionError(proxyAddr, host string, err error) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		fields := logrus.Fields{
			"proxy_addr": proxyAddr,
			"host":       host,
		}
		if err != nil {
			fields["error"] = err.Error()
		}
		logger.WithFields(fields).Debug("[StickyIP] DNS resolution failed (will use original domain)")
	}
}

func logDirectDial(proxyAddr, addr, network string) {
	if logger.IsLevelEnabled(logrus.TraceLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"target":     addr,
			"network":    network,
		}).Trace("[StickyIP] Direct dial (already an IP)")
	}
}

func logResolvedIPs(proxyAddr string, ips []net.IPAddr, port, network string) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		ipList := make([]string, 0, len(ips))
		for _, ip := range ips {
			if ip.IP != nil {
				ipList = append(ipList, ip.IP.String())
			}
		}
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"ips":        ipList,
			"port":       port,
			"network":    network,
			"count":      len(ipList),
		}).Debug("[StickyIP] Resolved proxy domain to IPs")
	}
}

func logTryingIP(proxyAddr, targetAddr, network string) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"target":     targetAddr,
			"network":    network,
		}).Debug("[StickyIP] Trying proxy IP")
	}
}

func logIPSuccess(proxyAddr, targetAddr, network, ipVersion string, cycle uint64) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr":  proxyAddr,
			"selected_ip": targetAddr,
			"network":     network,
			"ip_version":  ipVersion,
			"cycle":       cycle,
		}).Debug("[StickyIP] Successfully connected to proxy IP")
	}
}

func logIPFailure(proxyAddr, targetAddr string, err error) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"target":     targetAddr,
			"error":      err.Error(),
		}).Debug("[StickyIP] Failed to connect to proxy IP (will try next)")
	}
}

func logAllIPsFailed(proxyAddr string, lastErr error) {
	if logger.IsLevelEnabled(logrus.ErrorLevel) {
		fields := logrus.Fields{
			"proxy_addr": proxyAddr,
		}
		if lastErr != nil {
			fields["error"] = lastErr.Error()
		}
		logger.WithFields(fields).Error("[StickyIP] All proxy IPs failed")
	}
}
