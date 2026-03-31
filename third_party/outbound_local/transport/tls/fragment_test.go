package tls

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type fragmentTestConn struct {
	writes [][]byte
}

func (c *fragmentTestConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c *fragmentTestConn) Close() error                       { return nil }
func (c *fragmentTestConn) SetDeadline(_ time.Time) error      { return nil }
func (c *fragmentTestConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *fragmentTestConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *fragmentTestConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

var _ netproxy.Conn = (*fragmentTestConn)(nil)

func TestFragmentConnWrite_PassthroughNonTLSRecord(t *testing.T) {
	raw := &fragmentTestConn{}
	conn := NewFragmentConn(raw, 2, 2, 0, 0)

	payload := []byte("plain")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("unexpected write length: got %d want %d", n, len(payload))
	}
	if len(raw.writes) != 1 {
		t.Fatalf("unexpected write count: got %d want 1", len(raw.writes))
	}
	if !bytes.Equal(raw.writes[0], payload) {
		t.Fatalf("payload mismatch: got %x want %x", raw.writes[0], payload)
	}
}

func TestFragmentConnWrite_AggregatesFragmentsWithoutInterval(t *testing.T) {
	raw := &fragmentTestConn{}
	conn := NewFragmentConn(raw, 2, 2, 0, 0)

	record := []byte{
		0x16, 0x03, 0x03, 0x00, 0x06,
		'a', 'b', 'c', 'd', 'e', 'f',
		'X', 'Y',
	}
	n, err := conn.Write(record)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != len(record) {
		t.Fatalf("unexpected write length: got %d want %d", n, len(record))
	}
	if len(raw.writes) != 2 {
		t.Fatalf("unexpected write count: got %d want 2", len(raw.writes))
	}

	wantHello := []byte{
		0x16, 0x03, 0x03, 0x00, 0x02, 'a', 'b',
		0x16, 0x03, 0x03, 0x00, 0x02, 'c', 'd',
		0x16, 0x03, 0x03, 0x00, 0x02, 'e', 'f',
	}
	if !bytes.Equal(raw.writes[0], wantHello) {
		t.Fatalf("fragmented hello mismatch:\n got %x\nwant %x", raw.writes[0], wantHello)
	}
	if !bytes.Equal(raw.writes[1], []byte{'X', 'Y'}) {
		t.Fatalf("tail mismatch: got %x want %x", raw.writes[1], []byte{'X', 'Y'})
	}
}

func TestFragmentConnWrite_WritesFragmentsIndividuallyWithInterval(t *testing.T) {
	raw := &fragmentTestConn{}
	conn := NewFragmentConn(raw, 2, 2, 1, 1)

	record := []byte{
		0x16, 0x03, 0x03, 0x00, 0x06,
		'a', 'b', 'c', 'd', 'e', 'f',
		'X', 'Y',
	}
	n, err := conn.Write(record)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != len(record) {
		t.Fatalf("unexpected write length: got %d want %d", n, len(record))
	}
	if len(raw.writes) != 4 {
		t.Fatalf("unexpected write count: got %d want 4", len(raw.writes))
	}

	wantFragments := [][]byte{
		{0x16, 0x03, 0x03, 0x00, 0x02, 'a', 'b'},
		{0x16, 0x03, 0x03, 0x00, 0x02, 'c', 'd'},
		{0x16, 0x03, 0x03, 0x00, 0x02, 'e', 'f'},
		{'X', 'Y'},
	}
	for i := range wantFragments {
		if !bytes.Equal(raw.writes[i], wantFragments[i]) {
			t.Fatalf("write %d mismatch:\n got %x\nwant %x", i, raw.writes[i], wantFragments[i])
		}
	}
}
