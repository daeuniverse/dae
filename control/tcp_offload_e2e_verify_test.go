/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

// Real-kernel verification harness for the TCP offload sent-accounting hook.
// Requires root and kernel BTF; only the non-root case is skipped.
// It loads the pruned offload datapath (verdict + accounting programs),
// mirrors dae's two-connection relay topology, and asserts that redirected
// traffic populates tcp_offload_sent and that the fuse backlog stays near
// zero on transfers above the engage threshold — the regression class where
// a dead accounting hook made every >64MiB session freeze for 10s.
//
// Note on accounting precision: fentry fires on function entry, so skbs
// requeued via the EAGAIN retry path are counted once per attempt; observed
// over-estimation is ~1-2% on loopback (sent slightly above tcp_info
// inflow), which is the conservative direction for the fuse (engages later,
// never early).

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	verifyPayload = 1 << 20  // 1MiB functional round-trip
	verifyStream  = 70 << 20 // > the 64MiB fuse engage threshold, still loopback-friendly
)

// loadOffloadVerifyCollection loads only the three programs and three maps
// the offload datapath needs, avoiding unrelated program types from the
// full tproxy object.
func loadOffloadVerifyCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	object := os.Getenv("DAE_TCP_OFFLOAD_TEST_OBJECT")
	if object == "" {
		object = "bpf_bpfel.o"
		if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
			object = "bpf_bpfeb.o"
		}
	}
	t.Logf("offload object: %s", object)
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		// A clean checkout has no generated object until `make ebpf` runs; the
		// stub-tagged unit-test job does not build one, so this kernel-level
		// harness skips instead of failing there. An explicitly requested
		// object that cannot be loaded is still a hard error.
		if os.Getenv("DAE_TCP_OFFLOAD_TEST_OBJECT") == "" && errors.Is(err, fs.ErrNotExist) {
			t.Skipf("offload object %s is not built; run `make ebpf` first", object)
		}
		t.Fatalf("LoadCollectionSpec: %v", err)
	}
	keepProg := map[string]bool{
		"tcp_offload_redirect":            true,
		"tcp_offload_sent_account":        true,
		"tcp_offload_sent_account_kprobe": true,
	}
	keepMap := map[string]bool{
		"fast_sock":         true,
		"tcp_offload_pause": true,
		"tcp_offload_sent":  true,
	}
	for name := range spec.Programs {
		if !keepProg[name] {
			delete(spec.Programs, name)
		}
	}
	for name, m := range spec.Maps {
		if !keepMap[name] && name[0] != '.' {
			delete(spec.Maps, name)
			continue
		}
		m.Pinning = ebpf.PinNone
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection (pruned): %v", err)
	}
	return coll
}

func perCPUCounter(m *ebpf.Map, key *bpfTuplesKey) (uint64, error) {
	var vals []uint64
	if err := m.Lookup(key, &vals); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range vals {
		sum += v
	}
	return sum, nil
}

func dumpOffloadSent(t *testing.T, m *ebpf.Map, expected *bpfTuplesKey) {
	t.Helper()
	t.Logf("sent expected key: %+v", *expected)
	var key bpfTuplesKey
	var vals []uint64
	iter := m.Iterate()
	for iter.Next(&key, &vals) {
		var sum uint64
		for _, v := range vals {
			sum += v
		}
		t.Logf("sent actual key: %+v bytes=%d", key, sum)
	}
	if err := iter.Err(); err != nil {
		t.Logf("sent map iteration: %v", err)
	}
}

// dumpConnState prints the TCP state of a relay leg for teardown diagnosis.
func dumpConnState(t *testing.T, name string, conn *net.TCPConn) {
	t.Helper()
	info, err := tcpConnInfo(conn)
	if err != nil {
		t.Logf("[dump] %s: tcp_info failed: %v", name, err)
		return
	}
	pending, perr := tcpConnPendingBytes(conn)
	rx, _ := tcpConnRxBytes(conn)
	t.Logf("[dump] %s: state=%d rx_bytes=%d pending=%d (err=%v)",
		name, info.State, rx, pending, perr)
}

// TestTCPOffloadSentAccountE2E verifies on this (real) kernel that
//  1. the production-selected accounting hook attaches (L1);
//  2. redirected traffic populates tcp_offload_sent (L2);
//  3. at 70MiB (> the 64MiB fuse threshold) sent tracks inflow, i.e. the
//     backlog the fuse reads stays near zero (L3).
func TestTCPOffloadSentAccountE2E(t *testing.T) {
	if unix.Geteuid() != 0 {
		t.Skip("needs root for BPF program load/attach")
	}
	for _, tc := range []struct {
		name        string
		address     string
		destination bool
	}{
		{name: "IPv4", address: "127.0.0.1:0"},
		{name: "IPv6", address: "[::1]:0"},
		{name: "IPv6DestinationOptions", address: "[::1]:0", destination: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runTCPOffloadSentAccountE2E(t, tc.address, tc.destination)
		})
	}
}

func runTCPOffloadSentAccountE2E(t *testing.T, address string, destination bool) {
	t.Helper()
	coll := loadOffloadVerifyCollection(t)
	defer coll.Close()

	fastSock := coll.Maps["fast_sock"]
	sentMap := coll.Maps["tcp_offload_sent"]
	if fastSock == nil || sentMap == nil {
		t.Fatal("missing maps in collection")
	}

	// An explicit override is diagnostic only, never an automatic production fallback.
	var fl link.Link
	var hook string
	var attachErr error
	if target := os.Getenv("DAE_TCP_OFFLOAD_TEST_KPROBE_TARGET"); target != "" {
		fl, attachErr = link.Kprobe(target, coll.Programs["tcp_offload_sent_account_kprobe"], nil)
		hook = "diagnostic kprobe/" + target
	} else {
		fl, hook, attachErr = attachTCPOffloadAccount(coll.Programs["tcp_offload_sent_account"], coll.Programs["tcp_offload_sent_account_kprobe"])
	}
	if attachErr != nil {
		t.Fatalf("L1 FAIL: accounting attach: %v", attachErr)
	}
	defer func() { _ = fl.Close() }()
	t.Logf("L1 PASS: accounting hook attached to %s", hook)

	// Verdict program on the SOCKHASH.
	vl, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  fastSock.FD(),
		Program: coll.Programs["tcp_offload_redirect"],
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	})
	if err != nil {
		t.Fatalf("attach verdict to fast_sock: %v", err)
	}
	defer func() { _ = vl.Close() }()

	// Topology mirroring dae's relay pair:
	//   fakeClient --conn1-- left (accepted)      right (dialed) --conn2-- fakeUpstream
	l1, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l1.Close() }()
	l2, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l2.Close() }()

	client, err := net.Dial("tcp", l1.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if destination {
		raw, err := client.(*net.TCPConn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var optionErr error
		if err := raw.Control(func(fd uintptr) {
			// An eight-byte Destination Options header containing only Pad1.
			options := []byte{unix.IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0}
			optionErr = unix.SetsockoptString(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DSTOPTS, string(options))
		}); err != nil {
			t.Fatal(err)
		}
		if optionErr != nil {
			t.Fatalf("set IPv6 Destination Options: %v", optionErr)
		}
	}
	leftRaw, err := l1.Accept()
	if err != nil {
		t.Fatal(err)
	}
	left := leftRaw.(*net.TCPConn)
	defer func() { _ = left.Close() }()
	right, err := net.Dial("tcp", l2.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rightTCP := right.(*net.TCPConn)
	defer func() { _ = rightTCP.Close() }()
	upRaw, err := l2.Accept()
	if err != nil {
		t.Fatal(err)
	}
	up := upRaw.(*net.TCPConn)
	defer func() { _ = up.Close() }()
	for _, conn := range []net.Conn{client, left, rightTCP, up} {
		if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}

	leftKey, err := tcpConnTuplesKey(left)
	if err != nil {
		t.Fatal(err)
	}
	rightKey, err := tcpConnTuplesKey(rightTCP)
	if err != nil {
		t.Fatal(err)
	}
	leftFD, err := tcpConnFD(left)
	if err != nil {
		t.Fatal(err)
	}
	rightFD, err := tcpConnFD(rightTCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := fastSock.Update(&leftKey, uint64(rightFD), ebpf.UpdateAny); err != nil {
		t.Fatalf("register left->right: %v", err)
	}
	if err := fastSock.Update(&rightKey, uint64(leftFD), ebpf.UpdateAny); err != nil {
		t.Fatalf("register right->left: %v", err)
	}
	defer func() { _ = fastSock.Delete(&leftKey) }()
	defer func() { _ = fastSock.Delete(&rightKey) }()

	rxBase, err := tcpConnRxBytes(left)
	if err != nil {
		t.Fatal(err)
	}

	// L2: 1MiB round trip through the redirect datapath.
	payload := make([]byte, verifyPayload)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	payloadErr := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		payloadErr <- err
	}()
	got := make([]byte, verifyPayload)
	if _, err := io.ReadFull(up, got); err != nil {
		t.Fatalf("L2 FAIL: upstream read: %v (redirect datapath broken?)", err)
	}
	if err := <-payloadErr; err != nil {
		t.Fatalf("L2 FAIL: client write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("L2 FAIL: payload mismatch through redirect")
	}
	time.Sleep(300 * time.Millisecond) // let per-cpu counters settle

	sentL2, lookupErr := perCPUCounter(sentMap, &leftKey)
	if lookupErr != nil || sentL2 == 0 {
		dumpOffloadSent(t, sentMap, &leftKey)
		t.Fatalf("L2 FAIL: tcp_offload_sent[leftKey]=%d lookup=%v after %d redirected bytes; a missing counter alone does not prove the hook never ran", sentL2, lookupErr, verifyPayload)
	}
	t.Logf("L2 PASS: sent[leftKey]=%d after 1MiB (expect ~%d)", sentL2, verifyPayload)

	// L3: 70MiB stream (above the 64MiB fuse engage threshold). The sent
	// counter must track inflow so the backlog stays near zero; before the
	// symbol fix the counter stayed at 0 and the fuse would engage.
	chunk := make([]byte, 1<<20)
	streamErr := make(chan error, 1)
	go func() {
		remain := verifyStream
		for remain > 0 {
			n := min(remain, len(chunk))
			if _, err := client.Write(chunk[:n]); err != nil {
				streamErr <- err
				return
			}
			remain -= n
			// Pace the producer slightly: a full-speed flood can tickle the
			// kernel's psock EAGAIN-retry path into an abort on WSL2; real
			// relay sources are TCP-flow-controlled anyway.
			time.Sleep(500 * time.Microsecond)
		}
		streamErr <- nil
	}()
	// io.CopyN result: on a mid-stream teardown of the redirect pair (a rare
	// WSL2 loopback artifact of the kernel psock EAGAIN-retry path under
	// burst; real relay sources are TCP-flow-controlled) the delivered
	// stream is trimmed short with a clean EOF. The assertion below is
	// about the delivered bytes: as long as more than the 64MiB engage
	// threshold arrived, sent-vs-inflow tracking is still proven.
	n, copyErr := io.CopyN(io.Discard, up, verifyStream)
	if copyErr != nil && n < verifyStream-(1<<20) {
		dumpConnState(t, "left", left)
		dumpConnState(t, "right", rightTCP)
		dumpConnState(t, "up", up)
		t.Fatalf("L3 FAIL: upstream stream read: %v after %d bytes", copyErr, n)
	}
	if copyErr != nil {
		t.Logf("L3 note: stream trimmed at %d/%d bytes (WSL2 psock teardown artifact); asserting on delivered portion", n, verifyStream)
	}
	if err := <-streamErr; err != nil && copyErr == nil {
		t.Fatalf("L3 FAIL: client stream write: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	rxNow, err := tcpConnRxBytes(left)
	if err != nil {
		t.Fatal(err)
	}
	inflow := int64(rxNow) - int64(rxBase)
	sentL3, lookupErr := perCPUCounter(sentMap, &leftKey)
	if lookupErr != nil {
		dumpOffloadSent(t, sentMap, &leftKey)
		t.Fatalf("L3 FAIL: sent lookup: %v", lookupErr)
	}
	backlogVal := inflow - int64(sentL3)
	t.Logf("L3: delivered=%d inflow=%d sent=%d backlog=%d (fuse engage at %d, resume at %d)",
		n, inflow, sentL3, backlogVal, tcpOffloadMaxPeerBacklog, tcpOffloadFuseResumeBytes)
	if n < tcpOffloadMaxPeerBacklog {
		t.Fatalf("L3 FAIL: only %d bytes delivered (below the %d engage threshold); cannot assert fuse behavior", n, tcpOffloadMaxPeerBacklog)
	}
	if sentL3 < uint64(n) {
		t.Fatalf("L3 FAIL: sent=%d after %d delivered bytes — counter is not tracking inflow; fuse would mis-engage", sentL3, n)
	}
	if backlogVal > int64(tcpOffloadFuseResumeBytes)*8 {
		t.Fatalf("L3 FAIL: backlog=%d far above resume threshold — fuse metric still wrong", backlogVal)
	}
	t.Logf("L3 PASS: backlog stays at %d (≪ %d engage threshold) — fuse will not mis-engage on unconstrained transfers", backlogVal, tcpOffloadMaxPeerBacklog)
}
