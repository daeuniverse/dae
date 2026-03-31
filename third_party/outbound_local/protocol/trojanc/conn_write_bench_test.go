package trojanc

import (
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type discardConn struct{}

func (c *discardConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c *discardConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *discardConn) Close() error                       { return nil }
func (c *discardConn) SetDeadline(_ time.Time) error      { return nil }
func (c *discardConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *discardConn) SetWriteDeadline(_ time.Time) error { return nil }

var _ netproxy.Conn = (*discardConn)(nil)

func BenchmarkConnFirstWrite(b *testing.B) {
	baseMetadata, err := protocol.ParseMetadata("example.com:443")
	if err != nil {
		b.Fatalf("parse metadata failed: %v", err)
	}
	baseMetadata.IsClient = true
	payload := make([]byte, 64<<10)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		conn, err := NewConn(&discardConn{}, Metadata{Metadata: baseMetadata, Network: "tcp"}, "test-password")
		if err != nil {
			b.Fatalf("new conn failed: %v", err)
		}
		if _, err := conn.Write(payload); err != nil {
			b.Fatalf("write failed: %v", err)
		}
	}
}
