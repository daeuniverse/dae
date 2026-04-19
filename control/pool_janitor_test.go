package control

import (
	"testing"
	"time"
)

func waitForJanitorStop(t *testing.T, done <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s janitor to stop", name)
	}
}

func TestAuxiliaryPoolsCloseStopJanitors(t *testing.T) {
	udpPool := NewUdpEndpointPool()
	anyfromPool := NewAnyfromPool()
	snifferPool := NewPacketSnifferPool()

	udpDone := udpPool.janitorDone
	anyfromDone := anyfromPool.janitorDone
	snifferDone := snifferPool.janitorDone

	udpPool.Close()
	anyfromPool.Close()
	snifferPool.Close()

	waitForJanitorStop(t, udpDone, "udp endpoint pool")
	waitForJanitorStop(t, anyfromDone, "anyfrom pool")
	waitForJanitorStop(t, snifferDone, "packet sniffer pool")
}
