/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"context"
	"encoding/binary"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	daerrors "github.com/daeuniverse/dae/common/errors"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func buildTCPLinkLogFields(res *proxyDialResult, dialParam *proxyDialParam, dst netip.AddrPort, domain string, annotateOffload bool, offloaded bool, offloadReason string) logrus.Fields {
	fields := logrus.Fields{
		"network":  res.OrigNetworkType,
		"outbound": res.Outbound.Name,
		"policy":   res.Outbound.GetSelectionPolicy(),
		"dialer":   res.Dialer.Property().Name,
		"sniffed":  domain,
		"ip":       RefineAddrPortToShow(dst),
		"dscp":     dialParam.Dscp,
		"pname":    ProcessName2String(dialParam.ProcessName[:]),
		"mac":      Mac2String(dialParam.Mac[:]),
	}
	if !annotateOffload {
		return fields
	}
	fields["ebpf_offload"] = offloaded
	// Only output reason field if not globally disabled
	if !offloaded && offloadReason != "" && !isOffloadGloballyDisabledReason(offloadReason) {
		fields["ebpf_offload_reason"] = offloadReason
	}
	return fields
}

// isOffloadGloballyDisabledReason checks if the offload reason is a globally
// disabled reason (e.g., "eBPF offload disabled due to kernel bug").
func isOffloadGloballyDisabledReason(reason string) bool {
	return reason == "eBPF offload disabled due to kernel bug" || reason == "platform unsupported"
}

func (c *ControlPlane) handleConn(ctx context.Context, lConn net.Conn) (err error) {
	defer func() { _ = lConn.Close() }()

	// Get tuples and outbound first so we can decide whether sniffing is needed.
	// Converge IPv4-mapped IPv6 addresses before looking up eBPF routing tuples.
	src := common.ConvergeAddrPort(lConn.RemoteAddr().(*net.TCPAddr).AddrPort())
	dst := common.ConvergeAddrPort(lConn.LocalAddr().(*net.TCPAddr).AddrPort())
	routingResult, err := c.core.RetrieveRoutingResult(src, dst, consts.IPPROTO_TCP)
	if err != nil {
		if stderrors.Is(err, ebpf.ErrKeyNotExist) {
			// Graceful fallback: routing tuple might be unavailable due to race/window
			// during connection handoff. Continue with userspace routing instead of
			// aborting the TCP connection.
			routingResult = &bpfRoutingResult{
				Outbound: uint8(consts.OutboundControlPlaneRouting),
			}
			if c.log.IsLevelEnabled(logrus.DebugLevel) {
				c.log.WithFields(logrus.Fields{
					"src": src.String(),
					"dst": dst.String(),
				}).WithError(err).Debug("Routing tuple missing; fallback to userspace routing")
			}
		} else {
			return fmt.Errorf("failed to retrieve target info %v: %v", dst.String(), err)
		}
	}

	// DNS Fast Path: Check for DNS-over-TCP traffic (port 53).
	// DNS is a stateless protocol and doesn't need the connection tracking
	// features that TCP relay provides. This optimization handles DNS queries
	// directly through the DNS controller.
	// Uses bufio.Reader to peek at data without consuming it,
	// allowing proper fallback if this isn't DNS traffic.
	if dst.Port() == 53 {
		bufReader := bufio.NewReader(lConn)
		handled, dnsErr := c.handleTCPDnsFastPath(ctx, lConn, bufReader, src, dst, routingResult)
		if handled {
			// Connection was handled as DNS - any errors are already logged
			return dnsErr
		}
		// Not DNS traffic (or failed to read as DNS) - fall through to normal TCP handling
		// Wrap the connection to include buffered data that was peeked but not consumed
		lConn = &bufioConn{Conn: lConn, reader: bufReader}
	}

	var (
		domain     string
		lRelayConn netproxy.Conn = lConn
	)
	if c.shouldTryTcpSniff(dst, routingResult) {
		cacheKey := newTcpSniffNegKey(dst, routingResult)
		now := time.Now()
		if c.shouldSkipTcpSniffByNegativeCache(cacheKey, now) {
			if c.log.IsLevelEnabled(logrus.TraceLevel) {
				c.log.WithFields(logrus.Fields{
					"src": src.String(),
					"dst": dst.String(),
				}).Trace("Skip TCP sniffing by negative cache")
			}
		} else {
			probeConn, prefetched, ready, probeErr := prefetchForTcpSniff(lConn, tcpSniffFirstPayloadWait, tcpSniffPrefetchBytes)
			if probeErr != nil {
				return probeErr
			}
			if !ready {
				// No early payload; treat as non-sniffable to avoid stalling server-first/established flows.
				c.noteTcpSniffFailure(cacheKey, now)
				lRelayConn = probeConn
			} else if !isLikelyHttpOrTLSPrefix(prefetched) {
				// Fast reject for non HTTP/TLS prefixes.
				c.noteTcpSniffFailure(cacheKey, now)
				lRelayConn = probeConn
			} else {
				// ConnSniffer should be used later, so we cannot close it now.
				sniffer := sniffing.NewConnSniffer(probeConn, c.sniffingTimeout)
				defer func() { _ = sniffer.Close() }()
				lRelayConn = sniffer

				domain, err = sniffer.SniffTcp()
				if err != nil {
					// Best practice:
					// 1) Sniffing-domain errors (not applicable/need more/not found) should not break relay.
					// 2) Ignorable connection errors (EOF/reset/timeout) should not break relay.
					// 3) Other unexpected errors should fail fast instead of being silently hidden.
					if !sniffing.IsSniffingError(err) && !daerrors.IsIgnorableConnectionError(err) {
						return err
					}
					if !sniffing.IsSniffingError(err) {
						if c.log.IsLevelEnabled(logrus.DebugLevel) {
							c.log.WithError(err).WithFields(logrus.Fields{
								"src": src.String(),
								"dst": dst.String(),
							}).Debug("TCP sniffing encountered ignorable connection error; continue relay")
						}
					}
					// Non-sniffable or ignorable cases suppress repeated sniff attempts.
					c.noteTcpSniffFailure(cacheKey, now)
					domain = ""
				} else {
					// Any success means this flow signature is sniffable; clear suppression.
					c.clearTcpSniffNegative(cacheKey)
				}
			}
		}
	}

	dialParam := &proxyDialParam{
		Outbound:    consts.OutboundIndex(routingResult.Outbound),
		Domain:      domain,
		Mac:         routingResult.Mac,
		ProcessName: routingResult.Pname,
		Dscp:        routingResult.Dscp,
		Src:         src,
		Dest:        dst,
		Mark:        routingResult.Mark,
		Network:     "tcp",
	}
	// Dial and relay.
	rConn, res, err := c.routeDial(ctx, dialParam)
	if err != nil {
		if res != nil && res.Outbound != nil && stderrors.Is(err, ob.ErrNoAliveDialer) {
			res.Outbound.HandleNoAliveDialer(
				res.OrigNetworkType,
				res.SelectionNetworkTypeObj,
				src,
				dst,
				domain,
				res.IsDialIp,
			)
			return nil
		}
		if daerrors.IsIgnorableConnectionError(err) {
			return nil
		}
		return fmt.Errorf("failed to dial %v: %w", dst, err)
	}
	defer func() { _ = rConn.Close() }()

	offloaded := false
	offloadReason := ""
	annotateOffload := false

	// Log new TCP connections at Info level for visibility (consistent with UDP behavior)
	// Note: TCP connections are inherently "new" at this point, unlike UDP endpoints which may be reused
	if c.log.IsLevelEnabled(logrus.InfoLevel) {
		c.log.WithFields(buildTCPLinkLogFields(res, dialParam, dst, domain, annotateOffload, offloaded, offloadReason)).Infof("%v <-> %v", RefineSourceToShow(src, dst.Addr()), res.DialTarget)
	}

	if offloaded {
		return nil
	}

	if err = RelayTCP(lRelayConn, rConn); err != nil {
		if daerrors.IsIgnorableTCPRelayError(err) {
			return nil // ignore normal connection closure errors
		}
		return fmt.Errorf("handleTCP relay error: %w", err)
	}

	if c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.WithFields(logrus.Fields{
			"src": src.String(),
			"dst": dst.String(),
		}).Debug("TCP relay completed")
	}

	return nil
}

type RouteDialParam struct {
	Outbound    consts.OutboundIndex
	Domain      string
	Mac         [6]uint8
	Dscp        uint8
	ProcessName [16]uint8
	Src         netip.AddrPort
	Dest        netip.AddrPort
	Mark        uint32
}

func (c *ControlPlane) RouteDialTcp(p *RouteDialParam) (conn netproxy.Conn, err error) {
	return c.RouteDialTcpContext(context.Background(), p)
}

func (c *ControlPlane) RouteDialTcpContext(ctx context.Context, p *RouteDialParam) (conn netproxy.Conn, err error) {
	dialParam := &proxyDialParam{
		Outbound:    p.Outbound,
		Domain:      p.Domain,
		Mac:         p.Mac,
		Dscp:        p.Dscp,
		ProcessName: p.ProcessName,
		Src:         p.Src,
		Dest:        p.Dest,
		Mark:        p.Mark,
		Network:     "tcp",
	}
	conn, _, err = c.routeDial(ctx, dialParam)
	return conn, err
}

type WriteCloser interface {
	CloseWrite() error
}

// RelayTCP copies data bidirectionally between two connections.
// A relayCore orchestrates shared cancellation and force-close fallback.
func RelayTCP(lConn, rConn netproxy.Conn) (err error) {
	return RelayTCPContext(context.Background(), lConn, rConn)
}

// RelayTCPContext copies data bidirectionally between two connections with
// the given context. The context can be used to cancel the relay operation
// or set a deadline. A nil context is treated as context.Background().
func RelayTCPContext(ctx context.Context, lConn, rConn netproxy.Conn) (err error) {
	core := newRelayCore(lConn, rConn, defaultRelayCopyEngine{})
	return core.run(ctx)
}

// TCP DNS Fast Path constants
const (
	// TCPDNSFirstReadTimeout is the timeout for reading the first DNS query
	// to determine if the connection is DNS traffic.
	TCPDNSFirstReadTimeout = 5 * time.Second
	// TCPDNSNextReadTimeout is the timeout for reading subsequent queries
	// on an established DNS-over-TCP connection.
	TCPDNSNextReadTimeout = 60 * time.Second
	// TCPDNSMaxMessageSize is the maximum allowed DNS message size (64KB).
	TCPDNSMaxMessageSize = 65535
)

// tcpDnsBufPool is a pool for TCP DNS response buffers.
// DNS-over-TCP adds a 2-byte length prefix, so we allocate 2 extra bytes.
var tcpDnsBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 1026) // 1024 + 2 for length prefix
		return &buf
	},
}

// tcpDnsResponseWriter implements dnsmessage.ResponseWriter for TCP DNS.
// It handles the 2-byte length prefix required by the DNS-over-TCP protocol.
type tcpDnsResponseWriter struct {
	conn net.Conn
}

func (w *tcpDnsResponseWriter) Close() error {
	return w.conn.Close()
}

func (w *tcpDnsResponseWriter) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

func (w *tcpDnsResponseWriter) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

func (w *tcpDnsResponseWriter) WriteMsg(m *dnsmessage.Msg) error {
	data, err := m.Pack()
	if err != nil {
		return err
	}
	// DNS-over-TCP requires a 2-byte length prefix
	totalLen := 2 + len(data)

	// Use buffer pool for small messages
	if totalLen <= 1026 {
		bufPtr := tcpDnsBufPool.Get().(*[]byte)
		defer tcpDnsBufPool.Put(bufPtr)
		buf := (*bufPtr)[:totalLen]
		binary.BigEndian.PutUint16(buf[:2], uint16(len(data)))
		copy(buf[2:], data)
		_, err = w.conn.Write(buf)
		return err
	}

	// Fallback for large messages
	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint16(buf[:2], uint16(len(data)))
	copy(buf[2:], data)
	_, err = w.conn.Write(buf)
	return err
}

func (w *tcpDnsResponseWriter) Write(b []byte) (int, error) {
	// Write with length prefix
	totalLen := 2 + len(b)

	// Use buffer pool for small messages
	if totalLen <= 1026 {
		bufPtr := tcpDnsBufPool.Get().(*[]byte)
		defer tcpDnsBufPool.Put(bufPtr)
		buf := (*bufPtr)[:totalLen]
		binary.BigEndian.PutUint16(buf[:2], uint16(len(b)))
		copy(buf[2:], b)
		_, err := w.conn.Write(buf)
		return len(b), err
	}

	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint16(buf[:2], uint16(len(b)))
	copy(buf[2:], b)
	_, err := w.conn.Write(buf)
	return len(b), err
}

func (w *tcpDnsResponseWriter) TsigStatus() error {
	return nil
}

func (w *tcpDnsResponseWriter) TsigTimersOnly(bool) {}

func (w *tcpDnsResponseWriter) Hijack() {}

// readDnsMsgFromBufio reads a single DNS message from a buffered reader.
// DNS-over-TCP messages are prefixed with a 2-byte length field.
// Returns the message or error. Does not consume data on parse failure.
func readDnsMsgFromBufio(reader *bufio.Reader, timeout time.Duration, conn net.Conn) (*dnsmessage.Msg, error) {
	// Set read deadline
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
	}

	// Peek 2-byte length prefix first (don't consume)
	lenBuf, err := reader.Peek(2)
	if err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf)

	// Validate message size
	if length > TCPDNSMaxMessageSize {
		return nil, fmt.Errorf("DNS message too large: %d bytes (max %d)", length, TCPDNSMaxMessageSize)
	}
	if length < 12 {
		return nil, fmt.Errorf("DNS message too small: %d bytes (min 12)", length)
	}

	// Now read and consume the full message (length prefix + data)
	fullData, err := reader.Peek(int(2 + length))
	if err != nil {
		return nil, err
	}
	data := fullData[2:]

	// Parse DNS message before consuming
	var msg dnsmessage.Msg
	if err := msg.Unpack(data); err != nil {
		return nil, err
	}

	// Consume the data by discarding it
	_, err = reader.Discard(int(2 + length))
	if err != nil {
		return nil, err
	}

	return &msg, nil
}

// bufioConn wraps a net.Conn with a bufio.Reader, allowing buffered data
// to be read first before falling back to the underlying connection.
// This is used when DNS fast path detection fails and we need to pass
// the connection to normal TCP handling with any peeked data preserved.
type bufioConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufioConn) UnderlyingConn() net.Conn {
	return c.Conn
}

func (c *bufioConn) TakeRelaySegments() [][]byte {
	prefix := c.TakeRelayPrefix()
	if len(prefix) == 0 {
		return nil
	}
	return [][]byte{prefix}
}

// TakeRelayPrefix exposes already-buffered bytes so relay can flush them
// before switching back to the underlying TCP stream.
//
// The returned slice aliases the bufio.Reader buffer and is only safe for
// immediate synchronous use by the relay goroutine before the next read.
func (c *bufioConn) TakeRelayPrefix() []byte {
	if c == nil || c.reader == nil {
		return nil
	}
	buffered := c.reader.Buffered()
	if buffered == 0 {
		return nil
	}
	prefix, err := c.reader.Peek(buffered)
	if err != nil {
		return nil
	}
	if _, err := c.reader.Discard(buffered); err != nil {
		return nil
	}
	return prefix
}

func (c *bufioConn) CopyRelayRemainder(dst io.Writer, buf []byte) (int64, error) {
	if c == nil {
		return 0, nil
	}
	if c.reader == nil {
		return relayCopyDirect(dst, c.Conn, buf)
	}

	// Once buffered bytes are drained we can resume directly on the underlying
	// TCP sockets, allowing the normal splice-based fast path to continue.
	if c.reader.Buffered() == 0 {
		if dstConn, ok := dst.(netproxy.Conn); ok {
			if dstTCP, ok := unwrapRelayTCPConn(dstConn); ok {
				if srcTCP, ok := unwrapRelayTCPConn(c.Conn); ok {
					return io.Copy(dstTCP, srcTCP)
				}
			}
		}
		return relayCopyDirect(dst, c.Conn, buf)
	}

	return relayCopyDirect(dst, c.reader, buf)
}

func (c *bufioConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *bufioConn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

func (c *bufioConn) Close() error {
	return c.Conn.Close()
}

func (c *bufioConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *bufioConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *bufioConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *bufioConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *bufioConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// handleTCPDnsFastPath handles DNS-over-TCP transparent proxy.
// It reads DNS queries from the connection, processes them through the DNS controller,
// and writes responses back. Returns true if the connection was handled as DNS.
// Uses bufio.Reader to support peeking at data without consuming it,
// allowing proper fallback to normal TCP handling if this isn't DNS traffic.
func (c *ControlPlane) handleTCPDnsFastPath(ctx context.Context, lConn net.Conn, bufReader *bufio.Reader, src, dst netip.AddrPort, routingResult *bpfRoutingResult) (handled bool, err error) {
	// Try to read the first DNS query to verify this is actually DNS traffic
	msg, err := readDnsMsgFromBufio(bufReader, TCPDNSFirstReadTimeout, lConn)
	if err != nil {
		// Not a valid DNS query - not DNS traffic, fall through to normal TCP handling
		// The bufio.Reader has buffered but not consumed the data, so the caller
		// should use a bufioConn wrapper to preserve the buffered data.
		return false, nil
	}

	// Verify it's a query, not a response
	if msg.Response {
		// Received a response instead of a query - not DNS client traffic
		return false, nil
	}

	// This is DNS-over-TCP traffic - handle all queries on this connection
	if routingResult.Mark == 0 {
		routingResult.Mark = c.soMarkFromDae
	}

	writer := &tcpDnsResponseWriter{conn: lConn}
	req := &udpRequest{
		realSrc:       src,
		realDst:       dst,
		src:           src,
		lConn:         nil,
		routingResult: routingResult,
	}

	// Handle DNS queries in a loop (TCP connections can be persistent)
	for {
		// Handle the query
		err := c.dnsController.HandleWithResponseWriter_(ctx, msg, req, writer)
		if err != nil {
			if stderrors.Is(err, ErrDNSQueryConcurrencyLimitExceeded) {
				// REFUSED was already sent by the controller
				return true, nil
			}
			// Send SERVFAIL for other errors
			errMsg := new(dnsmessage.Msg)
			errMsg.SetRcode(msg, dnsmessage.RcodeServerFailure)
			_ = writer.WriteMsg(errMsg)
			if c.log.IsLevelEnabled(logrus.DebugLevel) {
				c.log.WithError(err).Debug("TCP DNS fast path failed; SERVFAIL sent")
			}
			return true, nil
		}

		// Try to read next query
		msg, err = readDnsMsgFromBufio(bufReader, TCPDNSNextReadTimeout, lConn)
		if err != nil {
			// Connection closed or timeout - normal termination
			if daerrors.IsIgnorableConnectionError(err) || err == io.EOF {
				return true, nil
			}
			// Other errors - log and close
			if c.log.IsLevelEnabled(logrus.DebugLevel) {
				c.log.WithError(err).Debug("TCP DNS connection read error")
			}
			return true, nil
		}

		if msg.Response {
			// Client sent a response - unexpected, close connection
			return true, nil
		}
	}
}
