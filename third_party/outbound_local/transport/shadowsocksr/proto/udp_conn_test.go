package proto

import (
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/pool"
	poolbytes "github.com/daeuniverse/outbound/pool/bytes"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

type recordingPacketConn struct {
	mu     sync.Mutex
	writes []recordedPacketWrite
}

type recordedPacketWrite struct {
	addr string
	data []byte
}

func (c *recordingPacketConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *recordingPacketConn) Write(p []byte) (int, error) {
	return c.WriteTo(p, "")
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}

func (c *recordingPacketConn) WriteTo(p []byte, addr string) (int, error) {
	clone := append([]byte(nil), p...)
	c.mu.Lock()
	c.writes = append(c.writes, recordedPacketWrite{addr: addr, data: clone})
	c.mu.Unlock()
	return len(p), nil
}

func (c *recordingPacketConn) Close() error                     { return nil }
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

type noOpProtocol struct{}

func (p *noOpProtocol) InitWithServerInfo(*ServerInfo)     {}
func (p *noOpProtocol) Encode(data []byte) ([]byte, error) { return append([]byte(nil), data...), nil }
func (p *noOpProtocol) Decode(data []byte) ([]byte, int, error) {
	return append([]byte(nil), data...), len(data), nil
}
func (p *noOpProtocol) EncodePkt(*poolbytes.Buffer) error { return nil }
func (p *noOpProtocol) SetData(data interface{})          {}
func (p *noOpProtocol) GetData() interface{}              { return nil }
func (p *noOpProtocol) GetOverhead() int                  { return 0 }
func (p *noOpProtocol) DecodePkt(data []byte) (pool.Bytes, error) {
	pb := pool.Get(len(data))
	copy(pb, data)
	return pb, nil
}

func TestPacketConnConcurrentWriteTo(t *testing.T) {
	t.Helper()

	recorder := &recordingPacketConn{}
	pc, err := NewPacketConn(recorder, &noOpProtocol{}, "1.1.1.1:53")
	if err != nil {
		t.Fatalf("NewPacketConn failed: %v", err)
	}

	targets := []string{
		"1.1.1.1:53",
		"8.8.8.8:53",
		"9.9.9.9:53",
		"208.67.222.222:53",
	}

	var wg sync.WaitGroup
	for _, target := range targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := pc.WriteTo([]byte("payload-"+target), target); err != nil {
				t.Errorf("WriteTo(%s) failed: %v", target, err)
			}
		}()
	}
	wg.Wait()

	if len(recorder.writes) != len(targets) {
		t.Fatalf("unexpected write count: got %d want %d", len(recorder.writes), len(targets))
	}

	seen := make(map[string]bool, len(targets))
	for _, write := range recorder.writes {
		addr := socks.SplitAddr(write.data)
		if addr == nil {
			t.Fatal("failed to parse encoded target addr")
		}
		target := addr.String()
		payload := string(write.data[len(addr):])
		if payload != "payload-"+target {
			t.Fatalf("payload mismatch for %s: got %q", target, payload)
		}
		seen[target] = true
	}

	for _, target := range targets {
		if !seen[target] {
			t.Fatalf("missing target write for %s", target)
		}
	}
}
