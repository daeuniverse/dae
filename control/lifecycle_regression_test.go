/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	componentdns "github.com/daeuniverse/dae/component/dns"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// TestConnPoolCloseDuringDialDiscardsConn locks in the connPool.closed guard:
// a get() that dialed while close() emptied the pool must discard the fresh
// connection instead of appending it to a dead pool nobody will ever close.
func TestConnPoolCloseDuringDialDiscardsConn(t *testing.T) {
	dialed := make(chan *lifecycleNetproxyConn)
	release := make(chan struct{})
	pool := newConnPool(1, func(context.Context) (netproxy.Conn, error) {
		conn := &lifecycleNetproxyConn{}
		dialed <- conn
		// Hold the dial open until the test has closed the pool, making
		// the close-during-dial interleaving deterministic.
		<-release
		return conn, nil
	})

	type result struct {
		conn *pipelinedConn
		err  error
	}
	getResult := make(chan result, 1)
	go func() {
		conn, err := pool.get(context.Background())
		getResult <- result{conn, err}
	}()

	fresh := <-dialed
	if err := pool.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	close(release)
	res := <-getResult
	if res.err == nil {
		res.conn.Close()
		t.Fatal("get during close: err = nil, want error")
	}
	if got := fresh.closeCount.Load(); got != 1 {
		t.Fatalf("fresh conn Close calls = %d, want 1", got)
	}
}

// TestTCPDnsResponseWriterArmsWriteDeadline asserts the DNS-over-TCP response
// writer bounds its writes: a stalled client must not pin the fastpath
// goroutine in an unbounded Write.
func TestTCPDnsResponseWriterArmsWriteDeadline(t *testing.T) {
	conn := &lifecycleDeadlineConn{}
	writer := &tcpDnsResponseWriter{conn: conn, record: func(int64) {}}
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	if err := writer.WriteMsg(msg); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	if !conn.armed.Load() {
		t.Fatal("WriteMsg never armed a write deadline")
	}
	if !conn.cleared.Load() {
		t.Fatal("WriteMsg did not clear the write deadline after writing")
	}
}

// lifecycleNetproxyConn is a minimal netproxy.Conn double that counts closes.
type lifecycleNetproxyConn struct {
	closeCount atomic.Int32
}

func (c *lifecycleNetproxyConn) Read(_ []byte) (int, error) { return 0, io.EOF }

func (c *lifecycleNetproxyConn) Write(b []byte) (int, error) { return len(b), nil }

func (c *lifecycleNetproxyConn) Close() error {
	c.closeCount.Add(1)
	return nil
}

func (c *lifecycleNetproxyConn) LocalAddr() net.Addr  { return nil }
func (c *lifecycleNetproxyConn) RemoteAddr() net.Addr { return nil }
func (c *lifecycleNetproxyConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *lifecycleNetproxyConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *lifecycleNetproxyConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

// lifecycleDeadlineConn records whether a write deadline was armed and
// subsequently cleared.
type lifecycleDeadlineConn struct {
	armed   atomic.Bool
	cleared atomic.Bool
}

func (c *lifecycleDeadlineConn) Read(_ []byte) (int, error) { return 0, io.EOF }

func (c *lifecycleDeadlineConn) Write(b []byte) (int, error) { return len(b), nil }

func (c *lifecycleDeadlineConn) Close() error { return nil }

func (c *lifecycleDeadlineConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c *lifecycleDeadlineConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }

func (c *lifecycleDeadlineConn) SetDeadline(_ time.Time) error { return nil }

func (c *lifecycleDeadlineConn) SetReadDeadline(_ time.Time) error { return nil }

func (c *lifecycleDeadlineConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.cleared.Store(true)
	} else {
		c.armed.Store(true)
	}
	return nil
}

// lifecycleTestDialer builds a concrete dialer so egress runtimes under test
// exercise real resourceMode refcounting.
func lifecycleTestDialer(name string) *componentdialer.Dialer {
	prop := &componentdialer.Property{Property: D.Property{
		Name: name, Protocol: "shadowsocks", Link: "ss://" + name, Address: name + ":443",
	}}
	return componentdialer.NewDialerContext(context.Background(),
		&errorDialer{err: stderrors.New("unused")},
		&componentdialer.GlobalOption{Log: discardLogger(), CheckInterval: time.Hour},
		componentdialer.InstanceOption{DisableCheck: true},
		prop)
}

func lifecycleTestRuntime(d *componentdialer.Dialer) *egressRuntime {
	rt := newEgressRuntime(nil, nil)
	rt.configureResources(nil, []*componentdialer.Dialer{d}, nil)
	return rt
}

// lifecycleFakeForwarder counts closes; S4-style protocol check uses it.
type lifecycleFakeForwarder struct{ closes atomic.Int32 }

func (f *lifecycleFakeForwarder) ForwardDNS(context.Context, []byte) (*dns.Msg, error) {
	return nil, nil
}

func (f *lifecycleFakeForwarder) Close() error {
	f.closes.Add(1)
	return nil
}

// TestDnsForwarderCloseDoubleCheckProtocol locks in the dnsForwardersClosed
// double-check: after closeAllDnsForwarders drains concurrent creators, the
// cache must be empty and every created forwarder must have been closed.
func TestDnsForwarderCloseDoubleCheckProtocol(t *testing.T) {
	orig := dnsForwarderFactory
	var createdMu sync.Mutex
	created := []*lifecycleFakeForwarder{}
	dnsForwarderFactory = func(_ *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		f := &lifecycleFakeForwarder{}
		createdMu.Lock()
		created = append(created, f)
		createdMu.Unlock()
		return f, nil
	}
	t.Cleanup(func() { dnsForwarderFactory = orig })

	c := &DnsController{dnsControllerStore: newDnsControllerStore()}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	const workers = 8
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			arg := &dialArgument{bestTarget: netip.MustParseAddrPort(fmt.Sprintf("10.0.0.%d:53", w+1))}
			for {
				select {
				case <-stop:
					return
				default:
				}
				up := &componentdns.Upstream{}
				if _, err := c.getOrCreateDnsForwarder(up, arg); err != nil && stderrors.Is(err, ErrDnsForwardersClosed) {
					return
				}
			}
		}(w)
	}
	time.Sleep(50 * time.Millisecond)
	_ = c.closeAllDnsForwarders()
	close(stop)
	wg.Wait()
	left := 0
	c.dnsForwarderCache.Range(func(_, _ any) bool { left++; return true })
	if left != 0 {
		t.Fatalf("forwarder cache retains %d entries after close + creator drain", left)
	}
	createdMu.Lock()
	defer createdMu.Unlock()
	for i, f := range created {
		if f.closes.Load() == 0 {
			t.Fatalf("created forwarder %d never closed (leak)", i)
		}
	}
}

// TestTCHookSetPartialCommitRetainsRecoverableTxn locks in the partial
// transaction protocol: a commit whose apply and internal restore both fail
// keeps the transaction (marked partial) so a later rollback can restore the
// snapshot, and upsert stays rejected until the transaction is resolved.
func TestTCHookSetPartialCommitRetainsRecoverableTxn(t *testing.T) {
	backend := &fakeTCHookBackend{}
	set := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())
	p1 := new(ebpf.Program)
	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	if err := set.stage(testTCHookSpec(1, p1)); err != nil {
		t.Fatal(err)
	}
	if err := set.commit(); err != nil {
		t.Fatal(err)
	}
	set.finalize()

	// Partial commit: the desired detach fails and the restore's re-attach
	// fails too, leaving the kernel between before and desired states.
	backend.attachErr = stderrors.New("attach boom")
	backend.closeErr = stderrors.New("close boom")
	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	if err := set.commit(); err == nil {
		t.Fatal("commit unexpectedly succeeded")
	}
	if !set.hasTransaction() {
		t.Fatal("partial commit dropped the transaction; rollback could never restore the snapshot")
	}
	// Immediate (non-transactional) mutation must stay rejected while a
	// transaction is active — otherwise a wedged txn could not be observed.
	if err := set.upsert(testTCHookSpec(2, p1)); err == nil {
		t.Fatal("upsert during active transaction unexpectedly succeeded")
	}

	// Once the transient kernel errors clear, rollback must restore the
	// snapshot and clear the transaction so future reloads work again.
	backend.attachErr = nil
	backend.closeErr = nil
	if err := set.rollback(); err != nil {
		t.Fatalf("rollback after transient errors cleared: %v", err)
	}
	if set.hasTransaction() {
		t.Fatal("rollback left the partial transaction behind")
	}
}

// TestConnStateJanitorRetiresRoutinglessTCPBackstop locks in the routing-less
// TCP backstop: an idle routing-less ACTIVE entry is retired by the janitor
// even without a stale threshold, while routing-bearing entries are not.
func TestConnStateJanitorRetiresRoutinglessTCPBackstop(t *testing.T) {
	f := newReloadRetirementCleanupFixture(t)
	nowNs, err := monotonicNowNano()
	if err != nil {
		t.Fatalf("monotonicNowNano: %v", err)
	}
	agedNs := nowNs - uint64(tcpConnStateRoutinglessBackstop) - uint64(time.Second.Nanoseconds())
	freshNs := nowNs - uint64(time.Second.Nanoseconds())
	dst := netip.MustParseAddrPort("198.51.100.30:443")
	routinglessStale := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.30:41001"), dst, unix.IPPROTO_TCP)
	routinglessFresh := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.30:41002"), dst, unix.IPPROTO_TCP)
	routingStale := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.30:41003"), dst, unix.IPPROTO_TCP)
	seedRoutinglessConnState(t, f.connState, routinglessStale, agedNs)
	seedRoutinglessConnState(t, f.connState, routinglessFresh, freshNs)
	seedConnState(t, f.connState, routingStale, agedNs, 0)

	f.plane.cleanupConnStateMapBeforeLocked(false, 0)

	if connStateExists(f.connState, routinglessStale) {
		t.Fatal("aged routing-less TCP entry survived the backstop")
	}
	if !connStateExists(f.connState, routinglessFresh) {
		t.Fatal("fresh routing-less TCP entry was deleted before the backstop")
	}
	if !connStateExists(f.connState, routingStale) {
		t.Fatal("routing-bearing TCP entry was deleted without a stale threshold")
	}
}

// seedRoutinglessConnState plants a conn_state entry with no routing
// metadata, mirroring what WAN egress records for direct traffic.
func seedRoutinglessConnState(t *testing.T, m *ebpf.Map, key bpfTuplesKey, lastSeenNs uint64) {
	t.Helper()
	value := bpfConnState{LastSeenNs: lastSeenNs, State: 0}
	if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed routing-less conn state: %v", err)
	}
}

// TestLazyConnPoolCloseDuringLazyInit locks in the getOrInit/closePool race
// fix: a pool created by a lazy init that lands after closePool observed
// pool==nil must still be closed (its connections' readLoops would otherwise
// leak), and the caller must see a closed pool instead of a live one.
func TestLazyConnPoolCloseDuringLazyInit(t *testing.T) {
	release := make(chan struct{})
	var fresh *connPool
	lazy := &lazyConnPool{}
	initDone := make(chan struct{})
	init := func() *connPool {
		fresh = newConnPool(1, func(context.Context) (netproxy.Conn, error) {
			return &lifecycleNetproxyConn{}, nil
		})
		close(initDone)
		<-release
		return fresh
	}

	getResult := make(chan *connPool, 1)
	go func() { getResult <- lazy.getOrInit(init) }()
	<-initDone
	if err := lazy.closePool(); err != nil {
		t.Fatalf("closePool: %v", err)
	}
	close(release)
	got := <-getResult
	if got != nil {
		t.Fatal("getOrInit returned a live pool after close raced the lazy init")
	}
	if fresh == nil || fresh.closed != true {
		t.Fatal("escaped pool was not closed by the getOrInit recheck")
	}
	if len(fresh.conns) != 0 {
		t.Fatalf("escaped pool still holds %d connections", len(fresh.conns))
	}
}

// TestReleaseFlowDeleteHonorsSameTupleRepins locks in the M1 invariant: the
// physical conn_state delete shares the generationsMu critical section with
// the unpin, so a same-tuple reconnect that re-pins before the dying flow's
// unpin keeps its entry alive, and the entry is only deleted when the last
// reference drops.
func TestReleaseFlowDeleteHonorsSameTupleRepins(t *testing.T) {
	connState := newJanitorTestMap(t, "conn_state_map")
	manager := NewSessionManager(context.Background())
	manager.udpBPF.Store(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: connState}})
	d := lifecycleTestDialer("pin-race")
	rt := lifecycleTestRuntime(d)
	dst := netip.MustParseAddrPort("198.51.100.40:443")
	key := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.40:42001"), dst, unix.IPPROTO_TCP)
	value := bpfConnState{LastSeenNs: 1, State: 0}
	value.Meta.Data.HasRouting = 1
	if err := connState.Update(&key, &value, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed conn state: %v", err)
	}

	binding := TcpFlowBinding{}
	binding.Route.PolicyEpoch = 0
	binding.Egress.Dialer = d
	oldFlow, err := manager.adoptTCP(&memoryLayoutConn{id: 1}, nil, binding, rt, []bpfTuplesKey{key})
	if err != nil {
		t.Fatalf("adopt old flow: %v", err)
	}
	newFlow, err := manager.adoptTCP(&memoryLayoutConn{id: 2}, nil, binding, rt, []bpfTuplesKey{key})
	if err != nil {
		t.Fatalf("adopt reconnecting flow on the same tuple: %v", err)
	}
	shard := &manager.pinnedShards[tuplesShardIndex(&key)]
	shard.mu.Lock()
	refs := shard.keys[key]
	shard.mu.Unlock()
	if refs != 2 {
		t.Fatalf("pinned refs after same-tuple re-adoption = %d, want 2", refs)
	}

	// The dying flow unpins 2->1: the delete must NOT fire while the
	// reconnecting flow still holds a reference.
	oldFlow.finish()
	if !connStateExists(connState, key) {
		t.Fatal("conn_state entry deleted while a same-tuple repin still held a reference")
	}
	shard.mu.Lock()
	refs = shard.keys[key]
	shard.mu.Unlock()
	if refs != 1 {
		t.Fatalf("pinned refs after old flow finish = %d, want 1", refs)
	}

	// Last reference drops: the entry is deleted (inside the same critical
	// section), leaving nothing for the janitor to exempt.
	newFlow.finish()
	if connStateExists(connState, key) {
		t.Fatal("conn_state entry leaked after the last pin dropped")
	}
}

// TestReleaseFlowSameTupleHammer races adopt/finish cycles over one tuple;
// the race detector and the final refcount/map consistency are the oracle.
func TestReleaseFlowSameTupleHammer(t *testing.T) {
	connState := newJanitorTestMap(t, "conn_state_map")
	manager := NewSessionManager(context.Background())
	manager.udpBPF.Store(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: connState}})
	d := lifecycleTestDialer("pin-hammer")
	rt := lifecycleTestRuntime(d)
	dst := netip.MustParseAddrPort("198.51.100.40:443")
	key := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.40:42002"), dst, unix.IPPROTO_TCP)
	value := bpfConnState{LastSeenNs: 1, State: 0}
	value.Meta.Data.HasRouting = 1
	if err := connState.Update(&key, &value, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed conn state: %v", err)
	}
	binding := TcpFlowBinding{}
	binding.Route.PolicyEpoch = 0
	binding.Egress.Dialer = d

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for round := range 50 {
				flow, err := manager.adoptTCP(&memoryLayoutConn{id: uint64(id*1000 + round)}, nil, binding, rt, []bpfTuplesKey{key})
				if err != nil {
					t.Errorf("adopt round %d: %v", round, err)
					return
				}
				flow.finish()
			}
		}(i)
	}
	wg.Wait()

	shard := &manager.pinnedShards[tuplesShardIndex(&key)]
	shard.mu.Lock()
	refs := shard.keys[key]
	shard.mu.Unlock()
	if refs != 0 {
		t.Fatalf("pinned refs after hammer = %d, want 0", refs)
	}
	if connStateExists(connState, key) {
		t.Fatal("conn_state entry survived after every flow finished")
	}
}

// TestFatalIngressLoopErrorCancelsAndStashesFirstError locks in the
// post-ready serve-death propagation contract: the first terminal ingress
// loop error is stashed for Serve() to return, the plane context is
// cancelled so Serve() stops blocking, and later errors never overwrite the
// first one.
func TestFatalIngressLoopErrorCancelsAndStashesFirstError(t *testing.T) {
	plane := &ControlPlane{log: discardLogger()}
	plane.ctx, plane.cancel = context.WithCancel(context.Background())

	plane.fatalIngressLoopError("accept", stderrors.New("accept boom"))
	select {
	case <-plane.ctx.Done():
	default:
		t.Fatal("fatalIngressLoopError did not cancel the plane context")
	}
	if plane.serveLoopErr == nil {
		t.Fatal("serveLoopErr not recorded")
	}
	if got := plane.serveLoopErr.Error(); !strings.Contains(got, "accept boom") {
		t.Fatalf("serveLoopErr = %q, want it to carry the first error", got)
	}

	// A second terminal error must never replace the first: the first one
	// is the root cause the caller should see.
	plane.fatalIngressLoopError("read-udp", stderrors.New("second boom"))
	if got := plane.serveLoopErr.Error(); strings.Contains(got, "second boom") {
		t.Fatalf("serveLoopErr was overwritten by a later error: %q", got)
	}
}
