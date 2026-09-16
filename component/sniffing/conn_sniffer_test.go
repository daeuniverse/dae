package sniffing

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// splitReader feeds a TLS ClientHello in two fragments: the first read round
// returns only half of the payload (forcing ErrNeedMore), the second returns
// the remainder.
type splitReader struct {
	data []byte
	gave int
}

func (r *splitReader) Read(p []byte) (int, error) {
	if r.gave >= len(r.data) {
		return 0, io.EOF
	}
	end := len(r.data) / 2
	if r.gave > 0 {
		end = len(r.data)
	}
	n := copy(p, r.data[r.gave:end])
	r.gave += n
	return n, nil
}

// TestSnifferDataReadyReopenAfterNeedMore guards the dataReady/Once pairing
// across multi-round stream sniffing. SniffTcp's loop reads fragment by
// fragment: readStreamOnce closes the current dataReady as soon as a round's
// data arrives, then ErrNeedMore (incomplete TLS record) installs a fresh
// dataReady channel. The fresh channel's Once must be reset too, otherwise
// closeDataReady never closes it and TakeRelayPrefix logs an
// abnormal-sniff-state warning on every multi-round connection.
func TestSnifferDataReadyReopenAfterNeedMore(t *testing.T) {
	s := &Sniffer{}
	s.reset(true, &splitReader{data: tlsStreamWindowsOdinGame}, nil, nil, 2*time.Second)
	defer func() { _ = s.Close() }()

	// SniffTcp loops internally across both fragments and succeeds. After
	// the loop the current dataReady (the one rebuilt on ErrNeedMore) must
	// be closed; without the Once reset it stays open forever.
	domain, err := s.SniffTcp()
	if err != nil {
		t.Fatalf("multi-round sniff: unexpected error: %v", err)
	}
	if !strings.Contains(domain, "odin.game.daum.net") {
		t.Fatalf("sniffed domain %q, want odin.game.daum.net", domain)
	}

	select {
	case <-s.dataReady:
	default:
		t.Fatal("dataReady not closed after multi-round sniffing: TakeRelayPrefix would warn and skip")
	}
}

// TestTakeRelayPrefixSingleRound verifies the normal single-read path still
// closes dataReady before TakeRelayPrefix runs, and that the relay prefix
// carries the full buffered payload.
func TestTakeRelayPrefixSingleRound(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	sniffer := NewConnSniffer(server, 2*time.Second)
	hello := tlsCurlIpsb
	go func() {
		_, _ = client.Write(hello)
	}()
	domain, err := sniffer.SniffTcp()
	if err != nil {
		t.Fatalf("sniff error: %v", err)
	}
	if !strings.Contains(domain, "ip.sb") {
		t.Fatalf("sniffed domain %q, want ip.sb", domain)
	}
	if got := sniffer.TakeRelayPrefix(); len(got) != len(hello) {
		t.Fatalf("TakeRelayPrefix returned %d bytes, want %d (full ClientHello)", len(got), len(hello))
	}
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "TakeRelayPrefix") {
			t.Fatalf("unexpected TakeRelayPrefix warning: %s", entry.Message)
		}
	}
}
