package control

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type mockDNSResponseWriter struct {
	remote net.Addr
	msg    *dnsmessage.Msg
}

type malformedAddr struct{}

func (malformedAddr) Network() string { return "udp" }
func (malformedAddr) String() string  { return "127.0.0.1" }

func (m *mockDNSResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 53}
}

func (m *mockDNSResponseWriter) RemoteAddr() net.Addr {
	return m.remote
}

func (m *mockDNSResponseWriter) WriteMsg(msg *dnsmessage.Msg) error {
	m.msg = msg.Copy()
	return nil
}

func (m *mockDNSResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (m *mockDNSResponseWriter) Close() error              { return nil }
func (m *mockDNSResponseWriter) TsigStatus() error         { return nil }
func (m *mockDNSResponseWriter) TsigTimersOnly(bool)       {}
func (m *mockDNSResponseWriter) Hijack()                   {}

func TestParseDNSListenerAddrPort_WildcardAndHostname(t *testing.T) {
	addr4, err := parseDNSListenerAddrPort(":53", false)
	if err != nil {
		t.Fatalf("parse wildcard v4 failed: %v", err)
	}
	if addr4.Port() != 53 || addr4.Addr() != UnspecifiedAddressA {
		t.Fatalf("unexpected wildcard v4 parse result: %v", addr4)
	}

	addr6, err := parseDNSListenerAddrPort(":53", true)
	if err != nil {
		t.Fatalf("parse wildcard v6 failed: %v", err)
	}
	if addr6.Port() != 53 || addr6.Addr() != UnspecifiedAddressAAAA {
		t.Fatalf("unexpected wildcard v6 parse result: %v", addr6)
	}

	hostnameAddr, err := parseDNSListenerAddrPort("localhost:5353", false)
	if err != nil {
		t.Fatalf("parse hostname bind failed: %v", err)
	}
	if hostnameAddr.Port() != 5353 {
		t.Fatalf("unexpected hostname bind port: %v", hostnameAddr.Port())
	}
	if hostnameAddr.Addr() != netip.MustParseAddr("0.0.0.0") {
		t.Fatalf("unexpected hostname bind addr fallback: %v", hostnameAddr.Addr())
	}
}

func TestDnsHandlerServeDNS_WildcardBindNoPanic(t *testing.T) {
	log := logrus.New()
	ctrl, err := NewDnsController(nil, &DnsControllerOption{Log: log})
	if err != nil {
		t.Fatalf("new dns controller: %v", err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })

	cp := &ControlPlane{dnsController: ctrl}
	cp.dnsListener = &DNSListener{endpoint: Endpoint{Addr: ":53"}}
	h := &dnsHandler{controller: cp, log: log}

	w := &mockDNSResponseWriter{
		remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12000},
	}
	req := new(dnsmessage.Msg)
	req.SetQuestion("example.com.", dnsmessage.TypeA)

	var panicked bool
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		h.ServeDNS(w, req)
	}()

	if panicked {
		t.Fatal("ServeDNS panicked on wildcard local bind")
	}
	if w.msg == nil {
		t.Fatal("expected SERVFAIL response, got nil")
	}
	if w.msg.Rcode != dnsmessage.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL rcode, got: %v", w.msg.Rcode)
	}
}

func TestDnsHandlerServeDNS_NilRemoteAddrNoPanic(t *testing.T) {
	log := logrus.New()
	ctrl, err := NewDnsController(nil, &DnsControllerOption{Log: log})
	if err != nil {
		t.Fatalf("new dns controller: %v", err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })

	cp := &ControlPlane{dnsController: ctrl}
	cp.dnsListener = &DNSListener{endpoint: Endpoint{Addr: "127.0.0.1:53"}}
	h := &dnsHandler{controller: cp, log: log}

	w := &mockDNSResponseWriter{remote: nil}
	req := new(dnsmessage.Msg)
	req.SetQuestion("example.com.", dnsmessage.TypeA)

	var panicked bool
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		h.ServeDNS(w, req)
	}()

	if panicked {
		t.Fatal("ServeDNS panicked on nil RemoteAddr")
	}
	if w.msg == nil {
		t.Fatal("expected SERVFAIL response, got nil")
	}
	if w.msg.Rcode != dnsmessage.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL rcode, got: %v", w.msg.Rcode)
	}
}

func TestDnsHandlerServeDNS_BadRemoteAddrFormatNoPanic(t *testing.T) {
	log := logrus.New()
	ctrl, err := NewDnsController(nil, &DnsControllerOption{Log: log})
	if err != nil {
		t.Fatalf("new dns controller: %v", err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })

	cp := &ControlPlane{dnsController: ctrl}
	cp.dnsListener = &DNSListener{endpoint: Endpoint{Addr: "127.0.0.1:53"}}
	h := &dnsHandler{controller: cp, log: log}

	w := &mockDNSResponseWriter{remote: malformedAddr{}}
	req := new(dnsmessage.Msg)
	req.SetQuestion("example.com.", dnsmessage.TypeA)

	var panicked bool
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		h.ServeDNS(w, req)
	}()

	if panicked {
		t.Fatal("ServeDNS panicked on malformed RemoteAddr")
	}
	if w.msg == nil {
		t.Fatal("expected SERVFAIL response, got nil")
	}
	if w.msg.Rcode != dnsmessage.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL rcode, got: %v", w.msg.Rcode)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestIsDNSClientWriteGoneError(t *testing.T) {
	err := &net.OpError{
		Op:  "write",
		Net: "tcp",
		Err: &os.SyscallError{Syscall: "write", Err: syscall.EPIPE},
	}
	if !isDNSClientWriteGoneError(err) {
		t.Fatal("expected broken pipe write error to be ignorable for DNS client write")
	}
}

func TestDNSTimeoutClassification(t *testing.T) {
	err := &net.OpError{
		Op:  "read",
		Net: "udp",
		Err: timeoutErr{},
	}
	if !isDNSTimeoutError(err) {
		t.Fatal("expected read timeout to be recognized as DNS timeout")
	}
	if isDNSClientWriteGoneError(err) {
		t.Fatal("read timeout should not be treated as client write-gone error")
	}

	wrapped := errors.Join(err)
	if !isDNSTimeoutError(wrapped) {
		t.Fatal("expected wrapped timeout to still be recognized")
	}
}
