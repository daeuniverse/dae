/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

const (
	// tcpSniffFailureThreshold is the number of consecutive sniff failures
	// before we temporarily skip sniffing on the same flow signature.
	// Set to 1 for faster suppression of non-sniffable protocols (SSH, etc.).
	tcpSniffFailureThreshold = uint8(1)
	// tcpSniffNegativeCacheTTL is the suppression duration for sniffing after
	// repeated NotApplicable/timeout failures.
	tcpSniffNegativeCacheTTL = 10 * time.Minute
	// tcpSniffPrefetchBytes is the number of leading bytes read for quick
	// protocol gating before entering full sniffing path.
	tcpSniffPrefetchBytes = 16
	// tcpSniffFirstPayloadWait bounds how long we wait for initial client data.
	// If no payload arrives quickly, we treat it as non-sniffable flow.
	tcpSniffFirstPayloadWait = 15 * time.Millisecond
)

// tcpSniffingExcludedPorts contains ports that are known to carry non-HTTP/TLS traffic.
// Connections to these ports skip sniffing entirely to avoid unnecessary delays.
// This includes common services like SSH, databases, and other application protocols.
var tcpSniffingExcludedPorts = map[uint16]bool{
	20:    true, // FTP Data
	21:    true, // FTP Control
	22:    true, // SSH
	25:    true, // SMTP
	53:    true, // DNS (TCP)
	119:   true, // NNTP
	123:   true, // NTP
	161:   true, // SNMP
	3306:  true, // MySQL
	5432:  true, // PostgreSQL
	6379:  true, // Redis
	9200:  true, // Elasticsearch
	27017: true, // MongoDB
	11211: true, // Memcached
}

type tcpSniffNegKey struct {
	dst   netip.AddrPort
	pname [16]uint8
	mac   [6]uint8
	dscp  uint8
}

type tcpSniffNegEntry struct {
	failures          uint8
	expiresAtUnixNano int64
}

type prefixedConn struct {
	net.Conn
	prefix []byte
	off    int
}

func (c *prefixedConn) TakeRelaySegments() [][]byte {
	prefix := c.TakeRelayPrefix()
	if len(prefix) == 0 {
		return nil
	}
	return [][]byte{prefix}
}

func (c *prefixedConn) CopyRelayRemainder(dst io.Writer, buf []byte) (int64, error) {
	return relayCopyDirect(dst, c.Conn, buf)
}

// TakeRelayPrefix returns the remaining prefetched bytes and marks them as
// consumed so relay can flush them without copying through the generic buffer.
func (c *prefixedConn) TakeRelayPrefix() []byte {
	if c.off >= len(c.prefix) {
		return nil
	}
	remaining := c.prefix[c.off:]
	c.off = len(c.prefix)
	return remaining
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(p, c.prefix[c.off:])
		c.off += n
		if n == len(p) {
			return n, nil
		}
		m, err := c.Conn.Read(p[n:])
		return n + m, err
	}
	return c.Conn.Read(p)
}

func newTcpSniffNegKey(dst netip.AddrPort, routingResult *bpfRoutingResult) tcpSniffNegKey {
	var key tcpSniffNegKey
	key.dst = dst
	if routingResult != nil {
		key.pname = routingResult.Pname
		key.mac = routingResult.Mac
		key.dscp = routingResult.Dscp
	}
	return key
}

func (c *ControlPlane) shouldTryTcpSniff(dst netip.AddrPort, routingResult *bpfRoutingResult) bool {
	if c.sniffingTimeout <= 0 {
		return false
	}
	if c.dialMode == consts.DialMode_Ip {
		return false
	}
	if routingResult == nil {
		return false
	}
	outbound := consts.OutboundIndex(routingResult.Outbound)
	// Reserved outbounds that don't benefit from sniffed domains.
	if outbound == consts.OutboundDirect || outbound == consts.OutboundBlock {
		return false
	}
	// Skip sniffing for ports known to carry non-HTTP/TLS traffic.
	// This avoids the 15ms timeout delay for protocols like SSH, databases, etc.
	if tcpSniffingExcludedPorts[dst.Port()] {
		return false
	}
	return true
}

func (c *ControlPlane) shouldSkipTcpSniffByNegativeCache(key tcpSniffNegKey, now time.Time) bool {
	if tcpSniffFailureThreshold == 0 || tcpSniffNegativeCacheTTL <= 0 {
		return false
	}
	c.tcpSniffNegMu.RLock()
	if c.tcpSniffNegSet == nil {
		c.tcpSniffNegMu.RUnlock()
		return false
	}
	entry, ok := c.tcpSniffNegSet[key]
	c.tcpSniffNegMu.RUnlock()
	if !ok {
		return false
	}
	if entry.expiresAtUnixNano <= 0 {
		return false
	}
	if entry.expiresAtUnixNano <= now.UnixNano() {
		// Lazy delete under write lock; concurrent deletes are harmless no-ops.
		c.tcpSniffNegMu.Lock()
		delete(c.tcpSniffNegSet, key)
		c.tcpSniffNegMu.Unlock()
		return false
	}
	return true
}

func (c *ControlPlane) noteTcpSniffFailure(key tcpSniffNegKey, now time.Time) {
	if tcpSniffFailureThreshold == 0 || tcpSniffNegativeCacheTTL <= 0 {
		return
	}

	c.tcpSniffNegMu.Lock()
	defer c.tcpSniffNegMu.Unlock()
	if c.tcpSniffNegSet == nil {
		c.tcpSniffNegSet = make(map[tcpSniffNegKey]tcpSniffNegEntry)
	}

	entry, ok := c.tcpSniffNegSet[key]
	if ok && entry.expiresAtUnixNano > 0 && entry.expiresAtUnixNano <= now.UnixNano() {
		entry = tcpSniffNegEntry{}
	}
	entry.failures++
	if entry.failures >= tcpSniffFailureThreshold {
		entry.failures = tcpSniffFailureThreshold
		entry.expiresAtUnixNano = now.Add(tcpSniffNegativeCacheTTL).UnixNano()
	}
	c.tcpSniffNegSet[key] = entry
}

func (c *ControlPlane) clearTcpSniffNegative(key tcpSniffNegKey) {
	c.tcpSniffNegMu.Lock()
	defer c.tcpSniffNegMu.Unlock()
	if c.tcpSniffNegSet == nil {
		return
	}
	delete(c.tcpSniffNegSet, key)
}

func (c *ControlPlane) clearAllTcpSniffNegative() {
	c.tcpSniffNegMu.Lock()
	defer c.tcpSniffNegMu.Unlock()
	clear(c.tcpSniffNegSet)
}

var httpLikePrefixes = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("HEAD "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("CONNECT "),
	[]byte("TRACE "),
	[]byte("PRI * HTTP/2.0"),
}

func hasPrefixOverlap(probed, prefix []byte) bool {
	if len(probed) == 0 || len(prefix) == 0 {
		return false
	}
	n := len(probed)
	if len(prefix) < n {
		n = len(prefix)
	}
	return bytes.EqualFold(probed[:n], prefix[:n])
}

func isLikelyHttpOrTLSPrefix(probed []byte) bool {
	if len(probed) == 0 {
		return false
	}
	// TLS record: ContentType=Handshake(22), version major=0x03.
	if probed[0] == 0x16 {
		if len(probed) == 1 {
			return true
		}
		return probed[1] == 0x03
	}
	for _, prefix := range httpLikePrefixes {
		if hasPrefixOverlap(probed, prefix) {
			return true
		}
	}
	return false
}

// prefetchForTcpSniff reads a small prefix with a tight deadline.
// If no payload arrives quickly, it returns ready=false so caller can skip sniffing.
// If payload is read, the returned conn will replay the prefetched bytes.
func prefetchForTcpSniff(conn net.Conn, wait time.Duration, maxBytes int) (wrapped net.Conn, prefetched []byte, ready bool, err error) {
	if wait <= 0 || maxBytes <= 0 {
		return conn, nil, true, nil
	}

	buf := make([]byte, maxBytes)
	deadline := time.Now().Add(wait)
	_ = conn.SetReadDeadline(deadline)
	n, readErr := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{})

	if n > 0 {
		prefetched = append([]byte(nil), buf[:n]...)
		return &prefixedConn{
			Conn:   conn,
			prefix: prefetched,
		}, prefetched, true, nil
	}
	if readErr == nil || errors.Is(readErr, io.EOF) {
		return conn, nil, false, nil
	}
	var netErr net.Error
	if errors.As(readErr, &netErr) && netErr.Timeout() {
		return conn, nil, false, nil
	}
	return conn, nil, false, readErr
}
