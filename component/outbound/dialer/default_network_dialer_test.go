package dialer

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

type recordingNetworkDialer struct {
	dialNetwork   string
	dialAddr      string
	lookupNetwork string
	lookupHost    string
	conn          netproxy.Conn
}

func (d *recordingNetworkDialer) DialContext(_ context.Context, network, addr string) (netproxy.Conn, error) {
	d.dialNetwork = network
	d.dialAddr = addr
	return d.conn, nil
}

func (d *recordingNetworkDialer) LookupIPAddr(_ context.Context, network, host string) ([]net.IPAddr, error) {
	d.lookupNetwork = network
	d.lookupHost = host
	return nil, nil
}

type bufferTuningConn struct {
	readBufferSize  int
	writeBufferSize int
}

func (c *bufferTuningConn) Read(_ []byte) (int, error) {
	return 0, nil
}

func (c *bufferTuningConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *bufferTuningConn) Close() error {
	return nil
}

func (c *bufferTuningConn) ReadFrom(_ []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}

func (c *bufferTuningConn) WriteTo(b []byte, _ string) (int, error) {
	return len(b), nil
}

func (c *bufferTuningConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *bufferTuningConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *bufferTuningConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func (c *bufferTuningConn) SetReadBuffer(size int) error {
	c.readBufferSize = size
	return nil
}

func (c *bufferTuningConn) SetWriteBuffer(size int) error {
	c.writeBufferSize = size
	return nil
}

func kernelSocketBufferSizes(t *testing.T, conn *net.UDPConn) (readSize, writeSize int) {
	t.Helper()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn() error = %v", err)
	}

	var controlErr error
	if err := rawConn.Control(func(fd uintptr) {
		readSize, controlErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if controlErr != nil {
			return
		}
		writeSize, controlErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	}); err != nil {
		t.Fatalf("RawConn.Control() error = %v", err)
	}
	if controlErr != nil {
		t.Fatalf("GetsockoptInt() error = %v", controlErr)
	}
	return readSize, writeSize
}

func TestDefaultNetworkDialerAddsDefaultsToPlainNetwork(t *testing.T) {
	parent := &recordingNetworkDialer{}
	dialer := newDefaultNetworkDialer(parent, 123, true)

	if _, err := dialer.DialContext(context.Background(), "udp", "proxy.example:443"); err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if got, want := parent.dialAddr, "proxy.example:443"; got != want {
		t.Fatalf("dial addr = %q, want %q", got, want)
	}

	magicNetwork, err := netproxy.ParseMagicNetwork(parent.dialNetwork)
	if err != nil {
		t.Fatalf("ParseMagicNetwork() error = %v", err)
	}
	if got, want := magicNetwork.Network, "udp"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}
	if got, want := magicNetwork.Mark, uint32(123); got != want {
		t.Fatalf("mark = %d, want %d", got, want)
	}
	if !magicNetwork.Mptcp {
		t.Fatal("mptcp = false, want true")
	}
}

func TestDefaultNetworkDialerMergesExistingMagicNetwork(t *testing.T) {
	parent := &recordingNetworkDialer{}
	dialer := newDefaultNetworkDialer(parent, 123, true)
	network := netproxy.MagicNetwork{Network: "tcp", Mark: 7, IPVersion: "6"}.Encode()

	if _, err := dialer.DialContext(context.Background(), network, "proxy.example:443"); err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}

	magicNetwork, err := netproxy.ParseMagicNetwork(parent.dialNetwork)
	if err != nil {
		t.Fatalf("ParseMagicNetwork() error = %v", err)
	}
	if got, want := magicNetwork.Network, "tcp"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}
	if got, want := magicNetwork.Mark, uint32(7); got != want {
		t.Fatalf("mark = %d, want %d", got, want)
	}
	if !magicNetwork.Mptcp {
		t.Fatal("mptcp = false, want true")
	}
	if got, want := magicNetwork.IPVersion, "6"; got != want {
		t.Fatalf("ip version = %q, want %q", got, want)
	}
}

func TestDefaultNetworkDialerForwardsLookupWithMergedNetwork(t *testing.T) {
	parent := &recordingNetworkDialer{}
	dialer := newDefaultNetworkDialer(parent, 456, false).(*defaultNetworkDialer)

	if _, err := dialer.LookupIPAddr(context.Background(), "tcp", "proxy.example"); err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if got, want := parent.lookupHost, "proxy.example"; got != want {
		t.Fatalf("lookup host = %q, want %q", got, want)
	}

	magicNetwork, err := netproxy.ParseMagicNetwork(parent.lookupNetwork)
	if err != nil {
		t.Fatalf("ParseMagicNetwork() error = %v", err)
	}
	if got, want := magicNetwork.Network, "tcp"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}
	if got, want := magicNetwork.Mark, uint32(456); got != want {
		t.Fatalf("mark = %d, want %d", got, want)
	}
	if magicNetwork.Mptcp {
		t.Fatal("mptcp = true, want false")
	}
}

func TestDefaultNetworkDialerTunesUdpSocketBuffers(t *testing.T) {
	conn := &bufferTuningConn{}
	parent := &recordingNetworkDialer{conn: conn}
	dialer := newDefaultNetworkDialer(parent, 0, false)

	if _, err := dialer.DialContext(context.Background(), "udp", "proxy.example:443"); err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if got, want := conn.readBufferSize, defaultUDPReadBufferSize; got != want {
		t.Fatalf("read buffer size = %d, want %d", got, want)
	}
	if got, want := conn.writeBufferSize, defaultUDPWriteBufferSize; got != want {
		t.Fatalf("write buffer size = %d, want %d", got, want)
	}
}

func TestDefaultNetworkDialerDoesNotTuneTcpSocketBuffers(t *testing.T) {
	conn := &bufferTuningConn{}
	parent := &recordingNetworkDialer{conn: conn}
	dialer := newDefaultNetworkDialer(parent, 0, false)

	if _, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443"); err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if got := conn.readBufferSize; got != 0 {
		t.Fatalf("read buffer size = %d, want 0", got)
	}
	if got := conn.writeBufferSize; got != 0 {
		t.Fatalf("write buffer size = %d, want 0", got)
	}
}

func TestDefaultNetworkDialerTunesWrappedUdpSocketBuffers(t *testing.T) {
	conn := &bufferTuningConn{}
	wrapped := netproxy.NewFakeNetPacketConn(
		conn,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000},
	)
	parent := &recordingNetworkDialer{conn: wrapped}
	dialer := newDefaultNetworkDialer(parent, 0, false)

	if _, err := dialer.DialContext(context.Background(), "udp", "proxy.example:443"); err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if got, want := conn.readBufferSize, defaultUDPReadBufferSize; got != want {
		t.Fatalf("wrapped read buffer size = %d, want %d", got, want)
	}
	if got, want := conn.writeBufferSize, defaultUDPWriteBufferSize; got != want {
		t.Fatalf("wrapped write buffer size = %d, want %d", got, want)
	}
}

func TestDefaultNetworkDialerTunesKernelUdpSocketBuffers(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	// Start from a deliberately small baseline so the post-dial kernel socket
	// state must reflect the dialer's buffer tuning rather than the host default.
	if err := conn.SetReadBuffer(16 << 10); err != nil {
		t.Fatalf("SetReadBuffer() baseline error = %v", err)
	}
	if err := conn.SetWriteBuffer(16 << 10); err != nil {
		t.Fatalf("SetWriteBuffer() baseline error = %v", err)
	}
	beforeRead, beforeWrite := kernelSocketBufferSizes(t, conn)

	parent := &recordingNetworkDialer{conn: conn}
	dialer := newDefaultNetworkDialer(parent, 0, false)
	if _, err := dialer.DialContext(context.Background(), "udp", "proxy.example:443"); err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}

	afterRead, afterWrite := kernelSocketBufferSizes(t, conn)
	if afterRead <= beforeRead {
		t.Fatalf("kernel read buffer = %d, want greater than baseline %d", afterRead, beforeRead)
	}
	if afterWrite <= beforeWrite {
		t.Fatalf("kernel write buffer = %d, want greater than baseline %d", afterWrite, beforeWrite)
	}
}
