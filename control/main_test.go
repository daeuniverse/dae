package control

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain installs a goroutine-leak fence over the whole control package.
//
// Rationale: the control plane runs several long-lived background goroutines
// (event ringbuf reader, conn-state janitor, packet-sniffer janitor, UDP
// endpoint janitor, DNS cache janitor/evictor). A leak regression in any of
// them silently grows the resident goroutine set until it destabilizes the
// data plane. goleak.VerifyTestMain makes that regression fail the test suite
// instead of showing up months later as a production problem.
//
// The ignore list below is deliberately limited to the package's OWN
// top-level background supervisors, matched by entry function so that a
// leaked per-connection or per-request goroutine is still caught. A goroutine
// that is legitimately still running because the test did not close its owner
// is a real leak (missing Close/drain) and SHOULD be surfaced.
func TestMain(m *testing.M) {
	// HasFunction does an exact map lookup, so the symbol must match the
	// runtime name precisely: a `go func(){}` inside startJanitor becomes
	// `startJanitor.func1`, and the for-loop body it spawns that appears at
	// the top of the leaked goroutine is `startJanitor.func1.1`. We ignore the
	// loop-body entry point (`.func1.1`), which is the frame actually on top.
	goleak.VerifyTestMain(m,
		// PacketSnifferPool / UDP endpoint pool / AnyfromPool expiry janitors
		// (loop body = .func1.1). Under -race the runtime name gains a
		// constructor prefix (e.g. NewPacketSnifferPool.(*PacketSnifferPool).…),
		// so both spellings are ignored because HasFunction is an exact map
		// lookup.
		goleak.IgnoreAnyFunction("github.com/daeuniverse/dae/control.(*PacketSnifferPool).startJanitor.func1.1"),
		goleak.IgnoreAnyFunction("github.com/daeuniverse/dae/control.NewPacketSnifferPool.(*PacketSnifferPool).startJanitor.func1.1"),
		goleak.IgnoreAnyFunction("github.com/daeuniverse/dae/control.(*UdpEndpointPool).startJanitor.func1.1"),
		goleak.IgnoreAnyFunction("github.com/daeuniverse/dae/control.NewUdpEndpointPool.(*UdpEndpointPool).startJanitor.func1.1"),
		goleak.IgnoreAnyFunction("github.com/daeuniverse/dae/control.(*AnyfromPool).startJanitor.func1.1"),
		goleak.IgnoreAnyFunction("github.com/daeuniverse/dae/control.NewAnyfromPool.(*AnyfromPool).startJanitor.func1.1"),
		// DNS cache janitor (explicitly does NOT watch baseContext).
		goleak.IgnoreAnyFunction("github.com/daeuniverse/dae/control.(*DnsController).startDnsCacheJanitor.func1"),
		// Third-party goroutine-pool supervisors (ants) — background by design.
		goleak.IgnoreAnyFunction("github.com/panjf2000/ants/v2.(*poolCommon).purgeStaleWorkers"),
		goleak.IgnoreAnyFunction("github.com/panjf2000/ants/v2.(*poolCommon).ticktock"),
		// outbound package init background goroutine.
		goleak.IgnoreAnyFunction("github.com/daeuniverse/dae/component/outbound/dialer.init.0.func1"),
		// The fork's direct-dial packet receiver registry is a process-global
		// epoll loop with no stop API (one loop shared by every direct
		// endpoint, alive for the process lifetime). Tests that dial a real
		// direct conn (udp_endpoint_receiver_test.go) start it on first use.
		goleak.IgnoreAnyFunction("github.com/daeuniverse/outbound/protocol/direct.(*packetReceiverRegistry).loop"),
	)
}
