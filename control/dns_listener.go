/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	daerrors "github.com/daeuniverse/dae/common/errors"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Endpoint struct {
	TCP  bool
	UDP  bool
	Addr string
}

var ErrBadLocalDNSBindFormat = errors.New("bad local dns bind format")

func ParseEndpoint(raw string) (endpoint Endpoint, err error) {
	_, perr := netip.ParseAddrPort(raw)
	if perr == nil {
		// try ip addr first
		return Endpoint{false, true, raw}, nil
	}
	// try tcp+udp://127.0.0.1:5335
	u, perr := url.Parse(raw)
	if perr != nil {
		err = fmt.Errorf("%w: %v", ErrBadLocalDNSBindFormat, perr)
		return
	}

	// scheme maybe "tcp+udp"
	schemes := strings.Split(u.Scheme, "+")

	endpoint.Addr = u.Host
	for _, s := range schemes {
		switch s {
		case "udp":
			endpoint.UDP = true
		case "tcp":
			endpoint.TCP = true
		default:
			err = fmt.Errorf(
				"%w: unsupported protocol: %s for %s",
				ErrBadLocalDNSBindFormat, s, raw,
			)
			return
		}
	}

	return
}

type DNSListener struct {
	log       *logrus.Logger
	tcpServer *dnsmessage.Server
	udpServer *dnsmessage.Server
	udpConn   net.PacketConn
	tcpLn     net.Listener
	endpoint  Endpoint
	mu        sync.Mutex

	controller atomic.Pointer[ControlPlane]
}

const dnsListenerShutdownTimeout = 5 * time.Second

// NewDNSListener creates a new DNS listener
func NewDNSListener(log *logrus.Logger, endpoint string, controller *ControlPlane) (*DNSListener, error) {
	e, err := ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	ret := &DNSListener{
		log:      log,
		endpoint: e,
	}
	ret.controller.Store(controller)

	return ret, nil
}

func (d *DNSListener) Addr() string {
	return d.endpoint.Addr
}

func (d *DNSListener) Controller() *ControlPlane {
	if d == nil {
		return nil
	}
	return d.controller.Load()
}

func (d *DNSListener) SwapController(controller *ControlPlane) {
	if d == nil {
		return
	}
	d.controller.Store(controller)
}

func (d *DNSListener) activateServer(server *dnsmessage.Server, network string) error {
	started := make(chan struct{})
	exited := make(chan error, 1)
	server.NotifyStartedFunc = func() {
		close(started)
	}

	go func() {
		exited <- server.ActivateAndServe()
	}()

	select {
	case <-started:
		// Keep the server pointer local to this goroutine. Start waits for the
		// readiness callback, so Stop cannot race an unstarted server.
		go func() {
			if err := <-exited; err != nil {
				d.log.Errorf("Failed to serve DNS %s listener: %v", network, err)
			}
		}()
		return nil
	case err := <-exited:
		if err == nil {
			return fmt.Errorf("DNS %s listener stopped before becoming ready", network)
		}
		return fmt.Errorf("failed to serve DNS %s listener: %w", network, err)
	}
}

// Start starts the DNS listener
func (d *DNSListener) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.udpServer != nil {
		return fmt.Errorf("DNS udp listener already started")
	}
	if d.tcpServer != nil {
		return fmt.Errorf("DNS tcp listener already started")
	}

	// Create DNS handler
	handler := &dnsHandler{
		listener: d,
		log:      d.log,
	}
	rollbackUDP := func() {
		if d.udpServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), dnsListenerShutdownTimeout)
			_ = d.udpServer.ShutdownContext(ctx)
			cancel()
			d.udpServer = nil
		}
		if d.udpConn != nil {
			_ = d.udpConn.Close()
			d.udpConn = nil
		}
	}

	if d.endpoint.UDP {
		// Bind synchronously so that Start reports bind failures to its
		// caller instead of surfacing them later from a goroutine.
		udpConn, err := net.ListenPacket("udp", d.Addr())
		if err != nil {
			return fmt.Errorf("failed to bind DNS UDP listener on %s: %w", d.Addr(), err)
		}
		udpServer := &dnsmessage.Server{
			Addr:       d.Addr(),
			Net:        "udp",
			Handler:    handler,
			UDPSize:    65535,
			PacketConn: udpConn,
		}
		d.udpConn = udpConn
		d.udpServer = udpServer
		d.log.Infof("Starting DNS UDP listener on %s", d.Addr())
		if err = d.activateServer(udpServer, "UDP"); err != nil {
			_ = udpConn.Close()
			d.udpConn = nil
			d.udpServer = nil
			return err
		}
	}

	if d.endpoint.TCP {
		tcpLn, err := net.Listen("tcp", d.Addr())
		if err != nil {
			// Roll back the already-active UDP server.
			rollbackUDP()
			return fmt.Errorf("failed to bind DNS TCP listener on %s: %w", d.Addr(), err)
		}
		tcpServer := &dnsmessage.Server{
			Addr:     d.Addr(),
			Net:      "tcp",
			Handler:  handler,
			Listener: tcpLn,
		}
		d.tcpLn = tcpLn
		d.tcpServer = tcpServer
		d.log.Infof("Starting DNS TCP listener on %s", d.Addr())
		if err = d.activateServer(tcpServer, "TCP"); err != nil {
			_ = tcpLn.Close()
			d.tcpLn = nil
			d.tcpServer = nil
			rollbackUDP()
			return err
		}
	}

	return nil
}

// Stop stops the DNS listener
func (d *DNSListener) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var errs []error

	// Stop UDP server
	if d.udpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), dnsListenerShutdownTimeout)
		if err := d.udpServer.ShutdownContext(ctx); err != nil {
			errs = append(errs, err)
		}
		cancel()
		if d.udpConn != nil {
			_ = d.udpConn.Close()
			d.udpConn = nil
		}
		d.udpServer = nil
	}

	// Stop TCP server
	if d.tcpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), dnsListenerShutdownTimeout)
		if err := d.tcpServer.ShutdownContext(ctx); err != nil {
			errs = append(errs, err)
		}
		cancel()
		if d.tcpLn != nil {
			_ = d.tcpLn.Close()
			d.tcpLn = nil
		}
		d.tcpServer = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to stop DNS servers: %v", errors.Join(errs...))
	}
	return nil
}

func dnsFallbackAddr(preferV6 bool) netip.Addr {
	if preferV6 {
		return UnspecifiedAddressAAAA
	}
	return UnspecifiedAddressA
}

// parseDNSListenerAddrPort parses listener bind address to AddrPort for request metadata.
// It is tolerant to wildcard/hostname forms (e.g. ":53", "localhost:53").
func parseDNSListenerAddrPort(raw string, preferV6 bool) (netip.AddrPort, error) {
	if addrPort, err := netip.ParseAddrPort(raw); err == nil {
		return addrPort, nil
	}

	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return netip.AddrPort{}, err
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}

	if i := strings.LastIndex(host, "%"); i >= 0 {
		// Strip IPv6 zone suffix, netip.ParseAddr does not accept zones.
		host = host[:i]
	}

	if host == "" || host == "*" {
		return netip.AddrPortFrom(dnsFallbackAddr(preferV6), uint16(port)), nil
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip, uint16(port)), nil
	}

	// Hostname or unknown format: keep port and fallback to unspecified address.
	return netip.AddrPortFrom(dnsFallbackAddr(preferV6), uint16(port)), nil
}

// dnsHandler implements the dns.Handler interface
type dnsHandler struct {
	listener *DNSListener
	log      *logrus.Logger

	// badClientAddrAlert paces the unusable-client-address report. The address
	// is client-controlled, so one broken or hostile peer would otherwise draw
	// one error line per request; the observation count carried by each
	// emitted line is the number of requests answered with SERVFAIL for this
	// reason, and the per-request detail stays available at debug.
	badClientAddrAlert pacedAlert
}

// dnsListenerBadClientAddrLogInterval paces the unusable-client-address
// warning. A peer whose address never parses keeps failing every request it
// sends, so an unpaced report is one line per request for as long as the peer
// keeps asking.
const dnsListenerBadClientAddrLogInterval = 30 * time.Second

// answerUnusableClientAddr answers SERVFAIL for a request whose client address
// could not be turned into an IP:port, and reports it once per pace instead of
// once per request. It is the single reporting point for every address-parsing
// failure in the listener path, so the failures cannot be counted per site and
// then lose their total.
func (h *dnsHandler) answerUnusableClientAddr(w dnsmessage.ResponseWriter, r *dnsmessage.Msg, reason string, detail error) {
	if h == nil {
		return
	}
	if h.log != nil {
		entry := h.log.WithField("reason", reason)
		if detail != nil {
			entry = entry.WithError(detail)
		}
		if h.log.IsLevelEnabled(logrus.DebugLevel) {
			entry.Debug("DNS listener: unusable client address; answering SERVFAIL")
		}
		if dropped, emit := h.badClientAddrAlert.observe(time.Now(), dnsListenerBadClientAddrLogInterval); emit {
			entry.Warnf("DNS listener: answering SERVFAIL for a request with an unusable client address (%s); "+
				"dropped=%d, reporting at most one line per %v", reason, dropped, dnsListenerBadClientAddrLogInterval)
		}
	}
	if w != nil && r != nil {
		m := new(dnsmessage.Msg)
		m.SetRcode(r, dnsmessage.RcodeServerFailure)
		_ = w.WriteMsg(m)
	}
}

func isDNSClientWriteGoneError(err error) bool {
	if err == nil {
		return false
	}
	if opErr, ok := errors.AsType[*net.OpError](err); ok && opErr.Op == "write" {
		return daerrors.IsIgnorableConnectionError(err) || daerrors.IsClosedConnection(err)
	}
	// Fallback for wrapped errors where net.OpError is lost.
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "write") && daerrors.ContainsIgnorableErrorPattern(errStr)
}

func isDNSTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// ServeDNS handles DNS requests
func (h *dnsHandler) ServeDNS(w dnsmessage.ResponseWriter, r *dnsmessage.Msg) {
	defer func() {
		if rec := recover(); rec != nil {
			h.log.Errorf("Panic in DNS listener handler: %v", rec)
			if w != nil && r != nil {
				m := new(dnsmessage.Msg)
				m.SetRcode(r, dnsmessage.RcodeServerFailure)
				_ = w.WriteMsg(m)
			}
		}
	}()

	if w == nil || r == nil {
		return
	}
	// A message with the QR bit set is a response, not a query. The UDP and
	// TCP fast paths reject these before routing; without the same gate here
	// a client could feed a response-formed message to the listener and have
	// its question section misrouted through request routing (a Reject
	// verdict would even evict a live cache family). Drop it silently, same
	// as the fast paths.
	if r.Response {
		return
	}
	controller := h.listener.Controller()
	uploadRecord := RecordUploadTraffic
	downloadRecord := RecordDownloadTraffic
	if controller != nil {
		uploadRecord = controller.runtimeUploadRecorder()
		downloadRecord = controller.runtimeDownloadRecorder()
	}
	w = wrapRuntimeTrackedDNSResponseWriter(w, downloadRecord)
	recordDNSListenerRequest(w, r, uploadRecord)

	// Create a fake udpRequest to pass to the DNS controller
	clientAddr := w.RemoteAddr()
	if clientAddr == nil {
		h.answerUnusableClientAddr(w, r, "nil RemoteAddr", nil)
		return
	}
	var clientIPPort netip.AddrPort

	// Parse client address
	host, portStr, err := net.SplitHostPort(clientAddr.String())
	if err != nil {
		h.answerUnusableClientAddr(w, r, "split host and port", err)
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		h.answerUnusableClientAddr(w, r, "parse port", err)
		return
	}

	if i := strings.LastIndex(host, "%"); i >= 0 {
		host = host[:i]
	}

	clientIP, err := netip.ParseAddr(host)
	if err != nil {
		h.answerUnusableClientAddr(w, r, "parse IP", err)
		return
	}

	clientIPPort = netip.AddrPortFrom(clientIP, uint16(port))
	preferV6 := clientIP.Is6() && !clientIP.Is4In6()
	listenerAddr := ":53"
	if controller != nil && controller.dnsListener != nil && controller.dnsListener.Addr() != "" {
		listenerAddr = controller.dnsListener.Addr()
	}
	realDst, err := parseDNSListenerAddrPort(listenerAddr, preferV6)
	if err != nil {
		h.log.WithError(err).Warnf("Failed to parse local DNS bind address %q, fallback to unspecified address", listenerAddr)
		realDst = netip.AddrPortFrom(dnsFallbackAddr(preferV6), 53)
	}

	// DNS listener traffic has no transparent-flow handoff, so it supplies
	// fixed control-plane routing facts to the compatibility request adapter.
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundControlPlaneRouting),
		Mark:     0,
		Must:     0,
		Mac:      [6]uint8{},
		Pname:    [16]uint8{},
		Pid:      0,
		Dscp:     0,
	}

	udpReq := &udpRequest{
		realSrc:        clientIPPort,
		realDst:        realDst,
		src:            clientIPPort,
		lConn:          nil,
		routingResult:  routingResult,
		uploadRecord:   uploadRecord,
		downloadRecord: downloadRecord,
	}

	if controller == nil {
		m := new(dnsmessage.Msg)
		m.SetRcode(r, dnsmessage.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	var activeController *DnsController
	err = withActiveDNSController(controller, nil, func(queryCtx context.Context, dnsController *DnsController) error {
		activeController = dnsController
		return dnsController.HandleWithResponseWriter_(queryCtx, r, udpReq, w)
	})
	if err != nil {
		if errors.Is(err, ErrDNSQueryConcurrencyLimitExceeded) {
			// REFUSED response has been written by DNS controller.
			return
		}
		if isDNSClientWriteGoneError(err) {
			if h.log.IsLevelEnabled(logrus.DebugLevel) {
				h.log.WithError(err).Debug("Drop DNS response because client connection is already gone")
			}
			return
		}
		if errors.Is(err, ErrDNSTruncated) && activeController != nil {
			// The upstream answer did not fit a single upstream datagram and no
			// TCP upgrade delivered it. RFC 7766 §5 keeps the query on TCP and
			// reports TC=1; answering SERVFAIL would tell the client the name
			// does not resolve instead of that the answer did not fit.
			activeController.noteDnsTruncatedReplyToClient()
			if writeErr := activeController.sendDnsTruncatedResponse_(r, udpReq, w); writeErr != nil && !isDNSClientWriteGoneError(writeErr) {
				if h.log.IsLevelEnabled(logrus.DebugLevel) {
					h.log.WithError(writeErr).Debug("Failed to write DNS truncated response")
				}
			}
			return
		}
		if isDNSTimeoutError(err) {
			h.log.WithError(err).Debug("DNS request handling timed out")
		} else {
			h.log.WithError(err).Error("Failed to handle DNS request")
		}
		// Send error response
		m := new(dnsmessage.Msg)
		m.SetRcode(r, dnsmessage.RcodeServerFailure)
		if writeErr := w.WriteMsg(m); writeErr != nil && !isDNSClientWriteGoneError(writeErr) {
			if h.log.IsLevelEnabled(logrus.DebugLevel) {
				h.log.WithError(writeErr).Debug("Failed to write DNS SERVFAIL response")
			}
		}
		return
	}
}
