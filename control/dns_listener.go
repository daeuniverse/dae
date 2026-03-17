/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
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
	log        *logrus.Logger
	tcpServer  *dnsmessage.Server
	udpServer  *dnsmessage.Server
	endpoint   Endpoint
	controller *ControlPlane
	mu         sync.Mutex
}

// NewDNSListener creates a new DNS listener
func NewDNSListener(log *logrus.Logger, endpoint string, controller *ControlPlane) (*DNSListener, error) {
	e, err := ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	ret := &DNSListener{
		log:        log,
		controller: controller,
		endpoint:   e,
	}

	return ret, nil
}

func (d *DNSListener) Addr() string {
	return d.endpoint.Addr
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
		controller: d.controller,
		log:        d.log,
	}

	if d.endpoint.UDP {
		// create dns servers
		d.udpServer = &dnsmessage.Server{
			Addr:    d.Addr(),
			Net:     "udp",
			Handler: handler,
			UDPSize: 65535,
		}

		// Start UDP server in goroutine
		go func() {
			d.log.Infof("Starting DNS UDP listener on %s", d.udpServer.Addr)
			if err := d.udpServer.ListenAndServe(); err != nil {
				d.log.Errorf("Failed to start DNS UDP listener: %v", err)
			}
		}()

	}
	// also for tcp server
	if d.endpoint.TCP {
		d.tcpServer = &dnsmessage.Server{
			Addr:    d.Addr(),
			Net:     "tcp",
			Handler: handler,
		}
		// Start TCP server in goroutine
		go func() {
			d.log.Infof("Starting DNS TCP listener on %s", d.tcpServer.Addr)
			if err := d.tcpServer.ListenAndServe(); err != nil {
				d.log.Errorf("Failed to start DNS TCP listener: %v", err)
			}
		}()
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
		if err := d.udpServer.Shutdown(); err != nil {
			errs = append(errs, err)
		}
		d.udpServer = nil
	}

	// Stop TCP server
	if d.tcpServer != nil {
		if err := d.tcpServer.Shutdown(); err != nil {
			errs = append(errs, err)
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
	controller *ControlPlane
	log        *logrus.Logger
}

func isDNSClientWriteGoneError(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "write" {
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

	// Create a fake udpRequest to pass to the DNS controller
	clientAddr := w.RemoteAddr()
	if clientAddr == nil {
		h.log.Errorf("Failed to parse client address: nil RemoteAddr")
		m := new(dnsmessage.Msg)
		m.SetRcode(r, dnsmessage.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	var clientIPPort netip.AddrPort

	// Parse client address
	host, portStr, err := net.SplitHostPort(clientAddr.String())
	if err != nil {
		h.log.Errorf("Failed to parse client address: %v", err)
		m := new(dnsmessage.Msg)
		m.SetRcode(r, dnsmessage.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		h.log.Errorf("Failed to parse client port: %v", err)
		m := new(dnsmessage.Msg)
		m.SetRcode(r, dnsmessage.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	if i := strings.LastIndex(host, "%"); i >= 0 {
		host = host[:i]
	}

	clientIP, err := netip.ParseAddr(host)
	if err != nil {
		h.log.Errorf("Failed to parse client IP: %v", err)
		m := new(dnsmessage.Msg)
		m.SetRcode(r, dnsmessage.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	clientIPPort = netip.AddrPortFrom(clientIP, uint16(port))
	preferV6 := clientIP.Is6() && !clientIP.Is4In6()

	listenerAddr := ":53"
	if h.controller != nil && h.controller.dnsListener != nil && h.controller.dnsListener.Addr() != "" {
		listenerAddr = h.controller.dnsListener.Addr()
	}
	realDst, err := parseDNSListenerAddrPort(listenerAddr, preferV6)
	if err != nil {
		h.log.WithError(err).Warnf("Failed to parse local DNS bind address %q, fallback to unspecified address", listenerAddr)
		realDst = netip.AddrPortFrom(dnsFallbackAddr(preferV6), 53)
	}

	// Create routing result (fake)
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundControlPlaneRouting),
		Mark:     0,
		Must:     0,
		Mac:      [6]uint8{},
		Pname:    [16]uint8{},
		Pid:      0,
		Dscp:     0,
	}

	// Handle the DNS request using the existing DNS controller
	udpReq := &udpRequest{
		realSrc:       clientIPPort,
		realDst:       realDst,
		src:           clientIPPort,
		lConn:         nil, // Not used in this context
		routingResult: routingResult,
	}

	err = h.controller.dnsController.HandleWithResponseWriter_(context.Background(), r, udpReq, w)
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
