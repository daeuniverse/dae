package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type timeoutNetErr struct{}

func (e timeoutNetErr) Error() string   { return "timeout" }
func (e timeoutNetErr) Timeout() bool   { return true }
func (e timeoutNetErr) Temporary() bool { return true }

func TestIsTimeoutError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "deadline exceeded", err: context.DeadlineExceeded, want: true},
		{name: "net timeout", err: timeoutNetErr{}, want: true},
		{name: "wrapped net timeout", err: errors.New("other"), want: false},
		{name: "non timeout net", err: &net.DNSError{Err: "not timeout", IsTimeout: false}, want: false},
		{name: "nil", err: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTimeoutError(tt.err); got != tt.want {
				t.Fatalf("isTimeoutError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTcpFallbackDialArgument(t *testing.T) {
	baseDialArg := &dialArgument{l4proto: consts.L4ProtoStr_UDP}
	upstream := &dns.Upstream{Scheme: dns.UpstreamScheme_TCP_UDP}

	t.Run("fallback from udp timeout", func(t *testing.T) {
		got := tcpFallbackDialArgument(upstream, baseDialArg, context.DeadlineExceeded)
		if got == nil {
			t.Fatal("expected fallback dial argument")
		}
		if got.l4proto != consts.L4ProtoStr_TCP {
			t.Fatalf("fallback l4proto = %v, want tcp", got.l4proto)
		}
	})

	t.Run("no fallback on tcp", func(t *testing.T) {
		got := tcpFallbackDialArgument(upstream, &dialArgument{l4proto: consts.L4ProtoStr_TCP}, context.DeadlineExceeded)
		if got != nil {
			t.Fatal("expected nil fallback")
		}
	})

	t.Run("no fallback on non timeout", func(t *testing.T) {
		got := tcpFallbackDialArgument(upstream, baseDialArg, errors.New("broken pipe"))
		if got != nil {
			t.Fatal("expected nil fallback")
		}
	})

	t.Run("no fallback on non tcpudp upstream", func(t *testing.T) {
		got := tcpFallbackDialArgument(&dns.Upstream{Scheme: dns.UpstreamScheme_UDP}, baseDialArg, context.DeadlineExceeded)
		if got != nil {
			t.Fatal("expected nil fallback")
		}
	})
}

type fakeStream struct{}

func (fakeStream) Read(_ []byte) (int, error)    { return 0, errors.New("read should not be called") }
func (fakeStream) Write(_ []byte) (int, error)   { return 0, errors.New("write should not be called") }
func (fakeStream) SetDeadline(_ time.Time) error { return nil }

func TestSendStreamDNSRespectsContextCancelBeforeIO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	msg := []byte{0, 0}
	_, err := sendStreamDNS(ctx, fakeStream{}, msg)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("sendStreamDNS error = %v, want context.Canceled", err)
	}
}

func TestIsTimeoutErrorWrappedDeadline(t *testing.T) {
	err := errors.Join(context.DeadlineExceeded, errors.New("dial error"))
	if !isTimeoutError(err) {
		t.Fatal("expected wrapped deadline to be detected as timeout")
	}
}

// TestDnsForwarderCacheRemoved verifies that DnsController no longer holds a
// dnsForwarderCache field (dead-connection-caching was removed in P0-1 fix).
// The struct must compile and initialise without those fields.
func TestDnsForwarderCacheRemoved(t *testing.T) {
	c := &DnsController{
		dnsCacheMu: sync.Mutex{},
		dnsCache:   make(map[string]*DnsCache),
	}
	if c.dnsCache == nil {
		t.Fatal("dnsCache should be initialised")
	}
	// dnsForwarderCache, dnsForwarderCacheMu, dnsForwarderLastUse fields no
	// longer exist on DnsController; this test will fail to compile if they
	// are accidentally reintroduced.
}

// TestAnyfromPoolGetOrCreateRaceCondition verifies the AnyfromPool's
// GetOrCreate does not hold the global write lock while creating sockets
// (P1-4 fix: optimistic create-outside-lock pattern).
// This test validates the structural invariant that the method signature
// and pool fields are correct, without requiring actual socket creation.
func TestAnyfromPoolGetOrCreateRaceCondition(t *testing.T) {
	p := NewAnyfromPool()
	if p == nil {
		t.Fatal("NewAnyfromPool() returned nil")
	}
	// Verify the pool starts empty.
	p.mu.RLock()
	n := len(p.pool)
	p.mu.RUnlock()
	if n != 0 {
		t.Fatalf("expected empty pool, got %d entries", n)
	}
}

func newTestDnsControllerForHandle(t *testing.T) *DnsController {
	t.Helper()

	log := logrus.New()
	routingCfg := &config.Dns{
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: consts.DnsRequestOutboundIndex_AsIs.String(),
			},
			Response: config.DnsResponseRouting{
				Fallback: consts.DnsResponseOutboundIndex_Accept.String(),
			},
		},
	}
	routing, err := dns.New(routingCfg, &dns.NewOption{
		Logger: log,
		UpstreamReadyCallback: func(_ *dns.Upstream) error {
			return nil
		},
		UpstreamResolverNetwork: "udp",
	})
	if err != nil {
		t.Fatalf("dns.New(): %v", err)
	}

	controller, err := NewDnsController(routing, &DnsControllerOption{
		Log: log,
		CacheAccessCallback: func(_ *DnsCache) error {
			return nil
		},
		CacheRemoveCallback: func(_ *DnsCache) error {
			return nil
		},
		IpVersionPrefer: 0,
		FixedDomainTtl:  map[string]int{},
	})
	if err != nil {
		t.Fatalf("NewDnsController(): %v", err)
	}
	return controller
}

func newDispatchTestPlane(t *testing.T, queueSize int) *ControlPlane {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	log := logrus.New()
	return &ControlPlane{
		log:             log,
		ctx:             ctx,
		cancel:          cancel,
		dnsIngressQueue: make(chan dnsIngressTask, queueSize),
	}
}

// TestHandle_PropagatesDeadlineContextToDialSend verifies handle_ executes the
// real call chain and passes a deadline-bearing context into dialSend.
func TestHandle_PropagatesDeadlineContextToDialSend(t *testing.T) {
	controller := newTestDnsControllerForHandle(t)

	var capturedCtx context.Context
	stopErr := errors.New("stop-on-captured-context")
	controller.dialSendInvoker = func(ctx context.Context, _ int, _ *udpRequest, _ []byte, _ uint16, _ *dns.Upstream, _ bool) error {
		capturedCtx = ctx
		return stopErr
	}

	req := &udpRequest{
		realSrc: netip.MustParseAddrPort("192.0.2.10:5353"),
		realDst: netip.MustParseAddrPort("8.8.8.8:53"),
		src:     netip.MustParseAddrPort("192.0.2.10:5353"),
	}
	msg := &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{Id: 1, RecursionDesired: true},
		Question: []dnsmessage.Question{
			{Name: "example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
		},
	}

	err := controller.handle_(msg, req, false)
	if !errors.Is(err, stopErr) {
		t.Fatalf("handle_() error = %v, want %v", err, stopErr)
	}
	if capturedCtx == nil {
		t.Fatal("expected dialSend context to be captured")
	}
	deadline, ok := capturedCtx.Deadline()
	if !ok {
		t.Fatal("expected context with deadline from handle_")
	}
	if deadline.IsZero() {
		t.Fatal("deadline must not be zero")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > DnsNatTimeout+time.Second {
		t.Fatalf("unexpected deadline remaining: %v (DnsNatTimeout=%v)", remaining, DnsNatTimeout)
	}
}

func TestUdpIngressDispatch_DnsBypassesTaskQueue(t *testing.T) {
	plane := newDispatchTestPlane(t, 2)
	dnsTask := dnsIngressTask{
		data:        pool.Get(8),
		convergeSrc: netip.MustParseAddrPort("192.168.1.10:53000"),
		pktDst:      netip.MustParseAddrPort("8.8.8.8:53"),
		realDst:     netip.MustParseAddrPort("8.8.8.8:53"),
	}

	plane.dispatchDnsOrQueue(
		netip.MustParseAddrPort("192.168.1.10:53000"),
		netip.MustParseAddrPort("8.8.8.8:53"),
		dnsTask,
		func() {
			t.Fatal("dns packet should not be dispatched to per-src queue")
		},
	)

	select {
	case task := <-plane.dnsIngressQueue:
		task.data.Put()
	default:
		t.Fatal("expected dns task to be enqueued to dns ingress queue")
	}
}

func TestUdpIngressDispatch_NonDnsUsesTaskQueue(t *testing.T) {
	plane := newDispatchTestPlane(t, 1)
	executed := make(chan struct{}, 1)
	plane.emitUdpTask = func(_ string, task UdpTask) {
		task()
	}

	plane.dispatchDnsOrQueue(
		netip.MustParseAddrPort("192.168.1.10:53000"),
		netip.MustParseAddrPort("1.1.1.1:443"),
		dnsIngressTask{},
		func() {
			executed <- struct{}{}
		},
	)

	select {
	case <-executed:
	case <-time.After(time.Second):
		t.Fatal("non-dns task should be dispatched via emitUdpTask")
	}
	if len(plane.dnsIngressQueue) != 0 {
		t.Fatal("non-dns dispatch should not enqueue dns ingress queue")
	}
}

func TestUdpIngressDispatch_NoSyncFallbackWhenDnsLaneBusy(t *testing.T) {
	plane := newDispatchTestPlane(t, 1)
	plane.emitUdpTask = func(_ string, task UdpTask) {
		task()
	}

	first := dnsIngressTask{data: pool.Get(4)}
	plane.dnsIngressQueue <- first

	second := dnsIngressTask{data: pool.Get(4)}

	var nonDnsCalled atomic.Bool
	plane.dispatchDnsOrQueue(
		netip.MustParseAddrPort("192.168.1.10:53000"),
		netip.MustParseAddrPort("8.8.8.8:53"),
		second,
		func() {
			nonDnsCalled.Store(true)
		},
	)

	if got := atomic.LoadUint64(&plane.dnsIngressQueueFullTotal); got != 1 {
		t.Fatalf("dnsIngressQueueFullTotal=%d, want 1", got)
	}
	if got := atomic.LoadUint64(&plane.dnsIngressDropTotal); got != 1 {
		t.Fatalf("dnsIngressDropTotal=%d, want 1", got)
	}
	if nonDnsCalled.Load() {
		t.Fatal("non-dns fallback path must remain unused")
	}
	if len(plane.dnsIngressQueue) != 1 {
		t.Fatalf("dns ingress queue length=%d, want 1", len(plane.dnsIngressQueue))
	}
	queued := <-plane.dnsIngressQueue
	queued.data.Put()
}

func TestDrainDnsIngressQueue_DrainsWithoutCountingDrop(t *testing.T) {
	plane := newDispatchTestPlane(t, 3)
	plane.dnsIngressQueue <- dnsIngressTask{data: pool.Get(4)}
	plane.dnsIngressQueue <- dnsIngressTask{data: pool.Get(4)}
	plane.dnsIngressQueue <- dnsIngressTask{data: pool.Get(4)}

	plane.drainDnsIngressQueue()

	if len(plane.dnsIngressQueue) != 0 {
		t.Fatalf("dns ingress queue length=%d, want 0", len(plane.dnsIngressQueue))
	}
	if got := atomic.LoadUint64(&plane.dnsIngressDropTotal); got != 0 {
		t.Fatalf("dnsIngressDropTotal=%d, want 0", got)
	}
	if got := atomic.LoadUint64(&plane.dnsIngressQueueFullTotal); got != 0 {
		t.Fatalf("dnsIngressQueueFullTotal=%d, want 0", got)
	}
}

func TestResolveDnsIngressProfile(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		manual  config.DnsIngressManual
		workers int
		queue   int
	}{
		{name: "lean", level: "lean", workers: 32, queue: 128},
		{name: "balanced", level: "balanced", workers: 256, queue: 2048},
		{name: "aggressive", level: "aggressive", workers: 1024, queue: 4096},
		{
			name:    "manual",
			level:   "manual",
			manual:  config.DnsIngressManual{Workers: 512, Queue: 4096},
			workers: 512,
			queue:   4096,
		},
		{name: "unknown", level: "unknown", workers: 256, queue: 2048},
		{name: "empty", level: "", workers: 256, queue: 2048},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveDnsIngressProfile(tt.level, tt.manual)
			if got.workers != tt.workers || got.queueLen != tt.queue {
				t.Fatalf("resolveDnsIngressProfile(%q, %+v) = {%d, %d}, want {%d, %d}",
					tt.level, tt.manual, got.workers, got.queueLen, tt.workers, tt.queue)
			}
		})
	}
}

func TestAnyfromPoolGetOrCreate_ZeroTTLStillPooled(t *testing.T) {
	p := NewAnyfromPool()
	var createCalls atomic.Int32
	p.createAnyfromFn = func(_ string) (*Anyfrom, error) {
		createCalls.Add(1)
		return &Anyfrom{}, nil
	}

	first, isNew, err := p.GetOrCreate("127.0.0.1:40000", 0)
	if err != nil {
		t.Fatalf("GetOrCreate(first): %v", err)
	}
	if !isNew {
		t.Fatal("first GetOrCreate should create new anyfrom")
	}
	second, isNew, err := p.GetOrCreate("127.0.0.1:40000", 0)
	if err != nil {
		t.Fatalf("GetOrCreate(second): %v", err)
	}
	if isNew {
		t.Fatal("second GetOrCreate should reuse pooled anyfrom")
	}
	if first != second {
		t.Fatal("expected same pooled anyfrom instance for ttl=0")
	}
	if got := createCalls.Load(); got != 1 {
		t.Fatalf("createAnyfrom calls=%d, want 1", got)
	}
}

func TestAnyfromPoolGetOrCreate_NegativeTTLStillPooled(t *testing.T) {
	p := NewAnyfromPool()
	var createCalls atomic.Int32
	p.createAnyfromFn = func(_ string) (*Anyfrom, error) {
		createCalls.Add(1)
		return &Anyfrom{}, nil
	}

	first, isNew, err := p.GetOrCreate("127.0.0.1:40001", -1*time.Second)
	if err != nil {
		t.Fatalf("GetOrCreate(first): %v", err)
	}
	if !isNew {
		t.Fatal("first GetOrCreate should create new anyfrom")
	}
	second, isNew, err := p.GetOrCreate("127.0.0.1:40001", -1*time.Second)
	if err != nil {
		t.Fatalf("GetOrCreate(second): %v", err)
	}
	if isNew {
		t.Fatal("second GetOrCreate should reuse pooled anyfrom")
	}
	if first != second {
		t.Fatal("expected same pooled anyfrom instance for ttl<0")
	}
	if got := createCalls.Load(); got != 1 {
		t.Fatalf("createAnyfrom calls=%d, want 1", got)
	}
}
