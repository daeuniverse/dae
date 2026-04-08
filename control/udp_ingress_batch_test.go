package control

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func readSingleUDPIngressBatchPacket(t *testing.T, conn *net.UDPConn, reader *udpIngressBatchReader) (pktBuf pool.PB, src netip.AddrPort, dst netip.AddrPort) {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	n, err := reader.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch() error = %v", err)
	}
	if n != 1 {
		t.Fatalf("ReadBatch() count = %d, want 1", n)
	}

	pkt, gotSrc, oob, ok := reader.Take(0)
	if !ok {
		t.Fatal("Take(0) = false, want true")
	}
	t.Cleanup(func() { pkt.Put() })

	gotDst := RetrieveOriginalDest(oob)
	if !gotDst.IsValid() {
		t.Fatal("RetrieveOriginalDest() returned invalid address")
	}
	return pkt, gotSrc, gotDst
}

func TestUdpIngressBatchReader_ReadBatchUDP4(t *testing.T) {
	listenConfig := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			return dialer.TproxyControl(c)
		},
	}
	packetConn, err := listenConfig.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen udp4 with tproxy unsupported: %v", err)
	}
	defer func() { _ = packetConn.Close() }()

	conn := packetConn.(*net.UDPConn)
	reader := newUDPIngressBatchReader(conn, 1)
	if reader == nil {
		t.Fatal("newUDPIngressBatchReader() returned nil")
		return
	}
	defer reader.Close()
	if _, ok := reader.pc.(*ipv4.PacketConn); !ok {
		t.Fatalf("reader.pc type = %T, want *ipv4.PacketConn", reader.pc)
	}

	client, err := net.Dial("udp4", conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial(udp4) error = %v", err)
	}
	defer func() { _ = client.Close() }()

	payload := []byte("udp4-batch")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	pkt, src, dst := readSingleUDPIngressBatchPacket(t, conn, reader)
	if got := string(pkt); got != string(payload) {
		t.Fatalf("payload = %q, want %q", got, string(payload))
	}

	clientSrc := client.LocalAddr().(*net.UDPAddr).AddrPort()
	if src != clientSrc {
		t.Fatalf("src = %v, want %v", src, clientSrc)
	}

	wantDst := mustParseAddrPort(conn.LocalAddr().String())
	if dst != wantDst {
		t.Fatalf("dst = %v, want %v", dst, wantDst)
	}
}

func TestUdpIngressBatchReader_ReadBatchDualStackUDP4(t *testing.T) {
	listenConfig := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			return udpDualStackListenControl(c)
		},
	}
	packetConn, err := listenConfig.ListenPacket(context.Background(), "udp6", "[::]:0")
	if err != nil {
		t.Skipf("listen dual-stack udp6 unsupported: %v", err)
	}
	defer func() { _ = packetConn.Close() }()

	conn := packetConn.(*net.UDPConn)
	reader := newUDPIngressBatchReader(conn, 1)
	if reader == nil {
		t.Fatal("newUDPIngressBatchReader() returned nil")
		return
	}
	defer reader.Close()
	if _, ok := reader.pc.(*ipv6.PacketConn); !ok {
		t.Fatalf("reader.pc type = %T, want *ipv6.PacketConn", reader.pc)
	}

	port := conn.LocalAddr().(*net.UDPAddr).Port
	client, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("Dial(udp4 over dual-stack) error = %v", err)
	}
	defer func() { _ = client.Close() }()

	payload := []byte("udp4-over-udp6-batch")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	pkt, src, dst := readSingleUDPIngressBatchPacket(t, conn, reader)
	if got := string(pkt); got != string(payload) {
		t.Fatalf("payload = %q, want %q", got, string(payload))
	}

	clientSrc := client.LocalAddr().(*net.UDPAddr).AddrPort()
	if common.ConvergeAddrPort(src) != common.ConvergeAddrPort(clientSrc) {
		t.Fatalf("src = %v, want %v", src, clientSrc)
	}

	wantDst := mustParseAddrPort(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if common.ConvergeAddrPort(dst) != wantDst {
		t.Fatalf("dst = %v, want %v", dst, wantDst)
	}
}
