/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"strings"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func writeRuntimeTrackedUDPAddrPort(conn *net.UDPConn, data []byte, addr netip.AddrPort, recordDownload func(int64)) error {
	recordDownload = normalizeTrafficRecord(recordDownload)
	n, err := conn.WriteToUDPAddrPort(data, addr)
	if n > 0 {
		recordDownload(int64(n))
	}
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func sendRuntimeTrackedPkt(log *logrus.Logger, data []byte, from netip.AddrPort, to netip.AddrPort, recordDownload func(int64)) error {
	recordDownload = normalizeTrafficRecord(recordDownload)
	if err := sendPkt(log, data, from, to, nil); err != nil {
		return err
	}
	// UDP datagrams are treated as all-or-nothing here: sendPkt returns nil only
	// after a full packet send, so len(data) is the correct accounted size.
	recordDownload(int64(len(data)))
	return nil
}

func sendRuntimeTrackedPktFresh(log *logrus.Logger, data []byte, from netip.AddrPort, to netip.AddrPort, recordDownload func(int64)) error {
	recordDownload = normalizeTrafficRecord(recordDownload)
	if err := sendPktFresh(log, data, from, to); err != nil {
		return err
	}
	// UDP datagrams are treated as all-or-nothing here: sendPktFresh returns nil
	// only after a full packet send, so len(data) is the correct accounted size.
	recordDownload(int64(len(data)))
	return nil
}

// sendRuntimeTrackedPktLegacyAnyfrom preserves the pre-85a1fc3c DNS reply
// injection behavior: bind exactly to the upstream address/port and send the
// packet back to the client through the pooled Anyfrom socket, without the
// newer listener-socket or address-family normalization paths.
func sendRuntimeTrackedPktLegacyAnyfrom(data []byte, from netip.AddrPort, to netip.AddrPort, recordDownload func(int64)) error {
	recordDownload = normalizeTrafficRecord(recordDownload)
	af, _, err := DefaultAnyfromPool.GetOrCreate(from, AnyfromTimeout)
	if err != nil {
		return err
	}
	if _, err := af.WriteToUDPAddrPort(data, to); err != nil {
		return err
	}
	recordDownload(int64(len(data)))
	return nil
}

func sendRuntimeTrackedPktViaListener(conn *net.UDPConn, data []byte, from netip.AddrPort, to netip.AddrPort, recordDownload func(int64)) error {
	recordDownload = normalizeTrafficRecord(recordDownload)
	if err := sendPktViaListener(conn, data, from, to); err != nil {
		return err
	}
	// UDP datagrams are treated as all-or-nothing here: sendPktViaListener
	// returns nil only after a full packet send, so len(data) is safe to record.
	recordDownload(int64(len(data)))
	return nil
}

type runtimeTrackedDNSResponseWriter struct {
	dnsmessage.ResponseWriter
	tcp            bool
	recordDownload func(int64)
}

func wrapRuntimeTrackedDNSResponseWriter(w dnsmessage.ResponseWriter, recordDownload func(int64)) dnsmessage.ResponseWriter {
	if w == nil {
		return nil
	}
	if _, ok := w.(*runtimeTrackedDNSResponseWriter); ok {
		return w
	}
	return &runtimeTrackedDNSResponseWriter{
		ResponseWriter: w,
		tcp:            dnsResponseWriterUsesTCP(w),
		recordDownload: normalizeTrafficRecord(recordDownload),
	}
}

func (w *runtimeTrackedDNSResponseWriter) WriteMsg(msg *dnsmessage.Msg) error {
	err := w.ResponseWriter.WriteMsg(msg)
	if err == nil {
		if n := dnsMessageWireLen(msg, w.tcp); n > 0 {
			w.recordDownload(int64(n))
		}
	}
	return err
}

func (w *runtimeTrackedDNSResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.recordDownload(int64(n))
	}
	return n, err
}

func (w *runtimeTrackedDNSResponseWriter) ConnectionState() *tls.ConnectionState {
	if stater, ok := w.ResponseWriter.(dnsmessage.ConnectionStater); ok {
		return stater.ConnectionState()
	}
	return nil
}

func recordDNSListenerRequest(w dnsmessage.ResponseWriter, msg *dnsmessage.Msg, recordUpload func(int64)) {
	recordUpload = normalizeTrafficRecord(recordUpload)
	if n := dnsMessageWireLen(msg, dnsResponseWriterUsesTCP(w)); n > 0 {
		recordUpload(int64(n))
	}
}

func dnsMessageWireLen(msg *dnsmessage.Msg, tcp bool) int {
	if msg == nil {
		return 0
	}
	n := msg.Len()
	if tcp {
		n += 2
	}
	return n
}

func dnsResponseWriterUsesTCP(w dnsmessage.ResponseWriter) bool {
	if w == nil {
		return false
	}
	addr := w.LocalAddr()
	if addr == nil {
		return false
	}
	return strings.HasPrefix(strings.ToLower(addr.Network()), "tcp")
}
