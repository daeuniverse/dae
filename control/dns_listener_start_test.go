package control

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestDNSListenerStartAndStop(t *testing.T) {
	listener, err := NewDNSListener(logrus.New(), "tcp+udp://127.0.0.1:0", &ControlPlane{})
	if err != nil {
		t.Fatalf("NewDNSListener() error = %v", err)
	}

	if err := listener.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := listener.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestDNSListenerStartAndStopFast(t *testing.T) {
	listener, err := NewDNSListener(logrus.New(), "tcp+udp://127.0.0.1:0", &ControlPlane{})
	if err != nil {
		t.Fatalf("NewDNSListener() error = %v", err)
	}

	if err := listener.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := listener.StopFast(); err != nil {
		t.Fatalf("StopFast() error = %v", err)
	}
}

func TestDNSListenerStartReportsBindError(t *testing.T) {
	hold, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer hold.Close()

	listener, err := NewDNSListener(logrus.New(), hold.LocalAddr().String(), &ControlPlane{})
	if err != nil {
		t.Fatalf("NewDNSListener() error = %v", err)
	}

	if err := listener.Start(); err == nil {
		t.Fatal("Start() error = nil, want bind failure")
	}
}
