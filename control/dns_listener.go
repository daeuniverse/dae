/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type DNSListener struct {
	log        *logrus.Logger
	addr       string
	udpServer  *dnsmessage.Server
	tcpServer  *dnsmessage.Server
	controller *ControlPlane
	mu         sync.Mutex
}

// NewDNSListener creates a new DNS listener
func NewDNSListener(log *logrus.Logger, addr string, controller *ControlPlane) *DNSListener {
	return &DNSListener{
		log:        log,
		addr:       addr,
		controller: controller,
	}
}

// Start starts the DNS listener
func (d *DNSListener) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.udpServer != nil || d.tcpServer != nil {
		return fmt.Errorf("DNS listener already started")
	}

	// Create DNS handler
	handler := &dnsHandler{
		controller: d.controller,
		log:        d.log,
	}

	// Create UDP server
	d.udpServer = &dnsmessage.Server{
		Addr:    d.addr,
		Net:     "udp",
		Handler: handler,
		UDPSize: 65535,
	}

	// Start UDP server in goroutine
	go func() {
		d.log.Infof("Starting DNS UDP listener on %s", d.addr)
		if err := d.udpServer.ListenAndServe(); err != nil {
			d.log.Errorf("Failed to start DNS UDP listener: %v", err)
		}
	}()

	// Create TCP server
	d.tcpServer = &dnsmessage.Server{
		Addr:    d.addr,
		Net:     "tcp",
		Handler: handler,
	}

	// Start TCP server in goroutine
	go func() {
		d.log.Infof("Starting DNS TCP listener on %s", d.addr)
		if err := d.tcpServer.ListenAndServe(); err != nil {
			d.log.Errorf("Failed to start DNS TCP listener: %v", err)
		}
	}()

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

// dnsHandler implements the dns.Handler interface
type dnsHandler struct {
	controller *ControlPlane
	log        *logrus.Logger
}

// ServeDNS handles DNS requests
func (h *dnsHandler) ServeDNS(w dnsmessage.ResponseWriter, r *dnsmessage.Msg) {
	// Create a fake udpRequest to pass to the DNS controller
	clientAddr := w.RemoteAddr()
	var clientIPPort netip.AddrPort
	
	// Parse client address
	host, portStr, err := net.SplitHostPort(clientAddr.String())
	if err != nil {
		h.log.Errorf("Failed to parse client address: %v", err)
		return
	}
	
	port, err := strconv.Atoi(portStr)
	if err != nil {
		h.log.Errorf("Failed to parse client port: %v", err)
		return
	}
	
	clientIP, err := netip.ParseAddr(host)
	if err != nil {
		h.log.Errorf("Failed to parse client IP: %v", err)
		return
	}
	
	clientIPPort = netip.AddrPortFrom(clientIP, uint16(port))

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
		realDst:       netip.MustParseAddrPort(h.controller.dnsListener.addr),
		src:           clientIPPort,
		lConn:         nil, // Not used in this context
		routingResult: routingResult,
	}

	err = h.controller.dnsController.HandleWithResponseWriter_(r, udpReq, w)
	if err != nil {
		h.log.Errorf("Failed to handle DNS request: %v", err)
		// Send error response
		m := new(dnsmessage.Msg)
		m.SetRcode(r, dnsmessage.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
}
