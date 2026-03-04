package control

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
)

func TestRelayTCP_ConnSnifferPeerCloseReturns(t *testing.T) {
	lLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lLn.Close()

	rLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rLn.Close()

	lClient, err := net.Dial("tcp", lLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer lClient.Close()

	lRelay, err := lLn.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer lRelay.Close()

	rClient, err := net.Dial("tcp", rLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rClient.Close()

	rRelay, err := rLn.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer rRelay.Close()

	sniffer := sniffing.NewConnSniffer(lRelay, 200*time.Millisecond)
	defer sniffer.Close()

	header := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := lClient.Write(header); err != nil {
		t.Fatal(err)
	}

	_, sniffErr := sniffer.SniffTcp()
	if sniffErr != nil && !sniffing.IsSniffingError(sniffErr) {
		t.Fatalf("unexpected sniff error: %v", sniffErr)
	}

	done := make(chan error, 1)
	go func() {
		done <- RelayTCP(sniffer, rRelay)
	}()

	body := bytes.Repeat([]byte("x"), 256<<10)
	if _, err := lClient.Write(body); err != nil {
		t.Fatal(err)
	}

	want := append(append([]byte(nil), header...), body...)
	got := make([]byte, len(want))
	_ = rClient.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(rClient, got); err != nil {
		t.Fatalf("failed to read relayed bytes: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("relayed payload mismatch")
	}

	if tcp, ok := rClient.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = rClient.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RelayTCP did not return after peer close")
	}
}
