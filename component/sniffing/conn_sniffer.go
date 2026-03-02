/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

type ConnSniffer struct {
	net.Conn
	*Sniffer
}

// spliceIncompatibleProtocols is a pure-documentation reference.
//
// splice(2) requires at least one file descriptor to be a pipe; passing two
// TCP sockets always returns EINVAL.  Real zero-copy for proxied traffic is
// handled in the BPF layer (bpf_sk_redirect_map).  The table below is kept
// solely for human reference — no map is allocated at runtime.
//
// Protocol                              Port(s)
// ──────────────────────────────────────────────────────────────────────────
// Terminal / remote-shell (PTY / character-at-a-time)
//   SSH, Telnet                          22, 23
//   rlogin, rsh                          513, 514
//   SSH alternate                        2222, 22222
// Mail
//   SMTP / SMTPS / submission            25, 465, 587
//   POP3 / POP3S                         110, 995
//   IMAP / IMAPS                         143, 993
//   ManageSieve                          4190
// File transfer
//   FTP data+control                     20, 21
//   rsync                                873
// Directory services
//   LDAP / LDAPS                         389, 636
//   LDAP Global Catalog                  3268, 3269
// VoIP / media signalling
//   SIP / SIPS                           5060, 5061
//   RTSP                                 554, 8554
// Remote desktop / GUI forwarding
//   RDP                                  3389
//   VNC                                  5900–5902
// Instant messaging
//   XMPP client / TLS / s2s              5222, 5223, 5269
// Chat / bulletin-board
//   IRC / IRC over TLS                   194, 6667, 6697
//   NNTP / NNTPS                         119, 563
// Relational databases
//   MS SQL Server / browser              1433, 1434
//   Oracle DB                            1521
//   MySQL / MariaDB / X Protocol         3306, 33060
//   PostgreSQL                           5432
//   IBM DB2                              50000
// NoSQL / in-memory stores
//   Redis / Sentinel                     6379, 26379
//   Memcached                            11211
//   MongoDB                              27017–27019
//   Cassandra (CQL)                      9042
//   Elasticsearch                        9200, 9300
// Message queues
//   MQTT / MQTT over TLS                 1883, 8883
//   AMQP (RabbitMQ) / AMQPS             5671, 5672
//   STOMP                                61613
// Distributed coordination / streaming
//   ZooKeeper                            2181
//   etcd client / peer                   2379, 2380
//   Apache Kafka                         9092
// Version control
//   Git smart protocol                   9418
//   Subversion (SVN)                     3690
// Authentication
//   Kerberos (large tickets use TCP)     88

func NewConnSniffer(conn net.Conn, timeout time.Duration) *ConnSniffer {
	s := &ConnSniffer{
		Conn:    conn,
		Sniffer: NewStreamSniffer(conn, timeout),
	}
	return s
}

func (s *ConnSniffer) Read(p []byte) (n int, err error) {
	return s.Sniffer.Read(p)
}

func (s *ConnSniffer) Close() (err error) {
	var errs []string
	if err = s.Sniffer.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if err = s.Conn.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// WriteTo implements io.WriterTo.
//
// Called by io.Copy when ConnSniffer is the source (client → server direction).
// Its sole purpose is to flush the sniff buffer (TLS ClientHello etc.) before
// handing the remainder of the stream to a plain io.Copy.  There is no splice
// attempt: splice(2) requires at least one pipe fd and always returns EINVAL
// when given two TCP sockets.  Real zero-copy is handled in the BPF layer.
//
// Data flow: ConnSniffer (client) → remote proxy/server
func (s *ConnSniffer) WriteTo(w io.Writer) (n int64, err error) {
	// Flush buffered sniff data (e.g. TLS ClientHello already read).
	if s.Sniffer != nil {
		s.Sniffer.readMu.Lock()
		if s.Sniffer.buf.Len() > 0 {
			n, err = s.Sniffer.buf.WriteTo(w)
			s.Sniffer.readMu.Unlock()
			if err != nil {
				return n, err
			}
		} else {
			s.Sniffer.readMu.Unlock()
		}
	}
	// Forward the rest of the stream from the underlying connection.
	copied, err := io.Copy(w, s.Conn)
	return n + copied, err
}

// ReadFrom implements io.ReaderFrom.
//
// Called by io.Copy when ConnSniffer is the destination (server → client
// direction).  Bypasses the read buffer and writes directly to the underlying
// connection via a plain io.Copy.
//
// Data flow: remote proxy/server → ConnSniffer (client)
func (s *ConnSniffer) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(s.Conn, r)
}
