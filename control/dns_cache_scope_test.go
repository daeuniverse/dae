package control

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type captureResponseWriter struct {
	mu  sync.Mutex
	msg *dnsmessage.Msg
}

func (w *captureResponseWriter) LocalAddr() net.Addr       { return nil }
func (w *captureResponseWriter) RemoteAddr() net.Addr      { return nil }
func (w *captureResponseWriter) TsigStatus() error         { return nil }
func (w *captureResponseWriter) TsigTimersOnly(bool)       {}
func (w *captureResponseWriter) Hijack()                   {}
func (w *captureResponseWriter) Close() error              { return nil }
func (w *captureResponseWriter) Write([]byte) (int, error) { return 0, nil }

func (w *captureResponseWriter) WriteMsg(msg *dnsmessage.Msg) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msg = msg.Copy()
	return nil
}

func (w *captureResponseWriter) Message() *dnsmessage.Msg {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.msg == nil {
		return nil
	}
	return w.msg.Copy()
}

func newScopedDnsController(t *testing.T) *DnsController {
	t.Helper()

	routing, err := componentdns.New(&config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: "asis"},
			Response: config.DnsResponseRouting{Fallback: "accept"},
		},
	}, &componentdns.NewOption{
		Logger: logrus.New(),
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	require.NoError(t, err)

	ctrl, err := NewDnsController(routing, &DnsControllerOption{
		Log:              logrus.New(),
		LifecycleContext: context.Background(),
		CacheAccessCallback: func(*DnsCache) error {
			return nil
		},
		CacheRemoveCallback: func(*DnsCache) error {
			return nil
		},
		NewCache: func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				NS:               ns,
				Extra:            extra,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = ctrl.Close()
	})
	return ctrl
}

func dnsAResponseMsg(name string, ip string) *dnsmessage.Msg {
	msg := new(dnsmessage.Msg)
	msg.SetReply(&dnsmessage.Msg{})
	msg.SetQuestion(name, dnsmessage.TypeA)
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName(name),
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP(ip).To4(),
		},
	}
	return msg
}

func dnsAnswerIPv4(t *testing.T, msg *dnsmessage.Msg) string {
	t.Helper()
	require.NotNil(t, msg)
	require.NotEmpty(t, msg.Answer)
	a, ok := msg.Answer[0].(*dnsmessage.A)
	require.True(t, ok)
	return netip.MustParseAddr(a.A.String()).String()
}

func TestDnsController_AsIsCacheIsScopedByResolver(t *testing.T) {
	originalFactory := dnsForwarderFactory
	defer func() {
		dnsForwarderFactory = originalFactory
	}()

	ctrl := newScopedDnsController(t)
	ctrl.bestDialerChooser = func(ctx context.Context, req *udpRequest, upstream *componentdns.Upstream) (*dialArgument, error) {
		return &dialArgument{
			l4proto:    consts.L4ProtoStr_UDP,
			ipversion:  consts.IpVersionStr_4,
			bestTarget: req.realDst,
		}, nil
	}

	var forwardCalls atomic.Int32
	dnsForwarderFactory = func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
			forwardCalls.Add(1)
			return dnsAResponseMsg("scope.test.", dialArg.bestTarget.Addr().String()), nil
		}}, nil
	}

	cacheReq := &udpRequest{
		realSrc:       netip.MustParseAddrPort("192.0.2.10:41000"),
		realDst:       netip.MustParseAddrPort("8.8.8.8:53"),
		routingResult: &bpfRoutingResult{},
	}
	baseKey := ctrl.cacheKey("scope.test.", dnsmessage.TypeA)
	cacheKey := ctrl.responseCacheKey(baseKey, cacheReq, consts.DnsRequestOutboundIndex_AsIs, nil)
	require.NoError(t, ctrl.UpdateDnsCacheTtlWithKey(cacheKey, "scope.test.", dnsmessage.TypeA, dnsAResponseMsg("scope.test.", "8.8.8.8").Answer, nil, nil, 60))

	query := new(dnsmessage.Msg)
	query.SetQuestion("scope.test.", dnsmessage.TypeA)
	writer := &captureResponseWriter{}
	req := &udpRequest{
		realSrc:       netip.MustParseAddrPort("192.0.2.11:42000"),
		realDst:       netip.MustParseAddrPort("1.1.1.1:53"),
		routingResult: &bpfRoutingResult{},
	}

	require.NoError(t, ctrl.HandleWithResponseWriter_(context.Background(), query, req, writer))
	require.Equal(t, "1.1.1.1", dnsAnswerIPv4(t, writer.Message()))
	require.EqualValues(t, 1, forwardCalls.Load(), "resolver-specific cache miss should forward upstream instead of reusing another resolver's answer")
}

func TestDnsController_AsIsSingleflightIsScopedByResolver(t *testing.T) {
	originalFactory := dnsForwarderFactory
	defer func() {
		dnsForwarderFactory = originalFactory
	}()

	ctrl := newScopedDnsController(t)
	ctrl.bestDialerChooser = func(ctx context.Context, req *udpRequest, upstream *componentdns.Upstream) (*dialArgument, error) {
		return &dialArgument{
			l4proto:    consts.L4ProtoStr_UDP,
			ipversion:  consts.IpVersionStr_4,
			bestTarget: req.realDst,
		}, nil
	}

	release := make(chan struct{})
	var forwardCalls atomic.Int32
	dnsForwarderFactory = func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
			forwardCalls.Add(1)
			<-release
			return dnsAResponseMsg("merge.test.", dialArg.bestTarget.Addr().String()), nil
		}}, nil
	}

	query1 := new(dnsmessage.Msg)
	query1.SetQuestion("merge.test.", dnsmessage.TypeA)
	query2 := new(dnsmessage.Msg)
	query2.SetQuestion("merge.test.", dnsmessage.TypeA)

	req1 := &udpRequest{
		realSrc:       netip.MustParseAddrPort("192.0.2.20:43000"),
		realDst:       netip.MustParseAddrPort("8.8.8.8:53"),
		routingResult: &bpfRoutingResult{},
	}
	req2 := &udpRequest{
		realSrc:       netip.MustParseAddrPort("192.0.2.21:44000"),
		realDst:       netip.MustParseAddrPort("1.1.1.1:53"),
		routingResult: &bpfRoutingResult{},
	}

	writer1 := &captureResponseWriter{}
	writer2 := &captureResponseWriter{}
	errCh := make(chan error, 2)

	go func() {
		errCh <- ctrl.HandleWithResponseWriter_(context.Background(), query1, req1, writer1)
	}()
	go func() {
		errCh <- ctrl.HandleWithResponseWriter_(context.Background(), query2, req2, writer2)
	}()

	require.Eventually(t, func() bool {
		return forwardCalls.Load() == 2
	}, 2*time.Second, 10*time.Millisecond, "different resolvers must not share a singleflight key")

	close(release)

	require.NoError(t, <-errCh)
	require.NoError(t, <-errCh)
	require.Equal(t, "8.8.8.8", dnsAnswerIPv4(t, writer1.Message()))
	require.Equal(t, "1.1.1.1", dnsAnswerIPv4(t, writer2.Message()))
}
