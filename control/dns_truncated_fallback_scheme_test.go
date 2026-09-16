/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// These tests keep the production forwarder constructor in the loop (the
// sibling tests replace the factory whole, which is what once hid a retry that
// could never be built), and they pin the two halves of the truncation contract
// that pull in opposite directions:
//
//   * a configured `udp://` upstream upgrades a TC=1 answer to TCP;
//   * an as-is destination is forwarded verbatim, so the client gets the
//     truncation signal the destination sent and dae opens no TCP connection
//     on its behalf.

// constructionCheckedFactory records the (scheme, transport) pairs the
// controller builds forwarders for and asserts the production constructor
// accepts each of them.
type constructionCheckedFactory struct {
	seen []string
	// serve is invoked with the transport the controller selected.
	serve func(l4proto consts.L4ProtoStr) (*dnsmessage.Msg, error)
}

func (f *constructionCheckedFactory) install(t *testing.T) {
	t.Helper()
	installCorpusDnsForwarderFactory(t, func(upstream *componentdns.Upstream, dialArg dialArgument, log *logrus.Logger) (DnsForwarder, error) {
		f.seen = append(f.seen, fmt.Sprintf("%s/%s", upstream.Scheme, dialArg.l4proto))
		if _, err := newDnsForwarder(upstream, dialArg, log); err != nil {
			return nil, err
		}
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			return f.serve(dialArg.l4proto)
		}}, nil
	})
}

// TestConfiguredUDPUpstreamTruncatedAnswerUpgradesOverTCP is the `udp://` half
// of the contract at the forwardWithFallback boundary: the retry has to be built
// from the rewritten TCP scheme, otherwise the production constructor rejects it
// with "unexpected scheme: udp" and the selection is thrown away.
func TestConfiguredUDPUpstreamTruncatedAnswerUpgradesOverTCP(t *testing.T) {
	const queryName = "udp-upstream-truncated-upgrade.test."

	factory := &constructionCheckedFactory{
		serve: func(l4proto consts.L4ProtoStr) (*dnsmessage.Msg, error) {
			switch l4proto {
			case consts.L4ProtoStr_UDP:
				return nil, ErrDNSTruncated
			case consts.L4ProtoStr_TCP:
				return dnsAResponseMsg(queryName, "198.51.100.89"), nil
			default:
				return nil, fmt.Errorf("unexpected transport %q", l4proto)
			}
		},
	}
	factory.install(t)

	ctrl := newCorpusDnsController(t, truncatedTestConfig())
	setScopedBestDialerChooser(ctrl, tcpAwareChooser(t,
		netip.MustParseAddrPort("198.51.100.53:53"), netip.MustParseAddrPort("198.51.100.53:53")))

	upstream := &componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_UDP,
		Hostname: "198.51.100.53",
		Port:     53,
	}
	primary := &dialArgument{l4proto: consts.L4ProtoStr_UDP, ipversion: consts.IpVersionStr_4, bestTarget: netip.MustParseAddrPort("198.51.100.53:53")}
	queryWire, err := corpusDnsQuery(0x5a11, queryName, dnsmessage.TypeA).Pack()
	require.NoError(t, err)

	respMsg, usedDialArg, err := ctrl.forwardWithFallback(context.Background(), defaultUdpRequest(), upstream, primary, queryWire, false)
	require.NoError(t, err)
	require.NotNil(t, usedDialArg)
	require.Equal(t, consts.L4ProtoStr_TCP, usedDialArg.l4proto)
	require.Len(t, respMsg.Answer, 1)
	require.Equal(t, []string{"udp/udp", "tcp/tcp"}, factory.seen)
	require.Equal(t, uint64(1), ctrl.dnsUdpTruncatedUpgrades.Load())
	require.Equal(t, uint64(0), ctrl.dnsUdpTruncatedUpgradeFailures.Load())
}

// TestAsIsTruncatedAnswerIsForwardedVerbatim is the as-is half. As-is means
// "ask the server the request was addressed to, as the request arrived", so a
// TC=1 answer is passed on: the client learns the answer did not fit and decides
// for itself whether to retry over TCP. dae must not open a second transport,
// must not run a second dialer selection, and must not turn the signal into
// SERVFAIL. Driven through the real DNS listener on both client transports.
func TestAsIsTruncatedAnswerIsForwardedVerbatim(t *testing.T) {
	for _, clientTransport := range []string{"udp", "tcp"} {
		t.Run(clientTransport, func(t *testing.T) {
			const queryName = "asis-truncated-passthrough.test."

			var (
				forwardCalls  atomic.Int32
				chooserCalls  atomic.Int32
				tcpForwarders atomic.Int32
			)
			installCorpusDnsForwarderFactory(t, func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
				require.Equal(t, componentdns.UpstreamScheme_UDP, upstream.Scheme)
				if dialArg.l4proto == consts.L4ProtoStr_TCP {
					tcpForwarders.Add(1)
				}
				return &stubDnsForwarder{forward: func(_ context.Context, data []byte) (*dnsmessage.Msg, error) {
					forwardCalls.Add(1)
					var q dnsmessage.Msg
					require.NoError(t, q.Unpack(data))
					// What a destination answers when its answer does not fit
					// its own UDP limit: NOERROR, TC=1, no records.
					truncated := new(dnsmessage.Msg)
					truncated.SetReply(&q)
					truncated.Truncated = true
					return truncated, ErrDNSTruncated
				}}, nil
			})

			ctrl := newCorpusDnsController(t, truncatedTestConfig())
			setScopedBestDialerChooser(ctrl, func(_ context.Context, snapshot DnsRequestSnapshot, _ *componentdns.Upstream) (*dialArgument, error) {
				chooserCalls.Add(1)
				return &dialArgument{l4proto: consts.L4ProtoStr_UDP, ipversion: consts.IpVersionStr_4, bestTarget: snapshot.RealDst}, nil
			})

			writer := serveDNSQueryThroughListener(t, ctrl, clientTransport, queryName, 0x7a01)
			got := writer.Message()
			require.NotNil(t, got, "the client must receive a response")
			require.Equal(t, dnsmessage.RcodeSuccess, got.Rcode, "a truncated answer is not a failure: SERVFAIL would claim the name does not resolve")
			require.True(t, got.Truncated, "the client must be told the answer did not fit")
			require.Empty(t, got.Answer, "a truncated response carries no answer records")
			require.Equal(t, uint16(0x7a01), got.Id)

			require.Equal(t, int32(1), forwardCalls.Load(), "exactly one upstream exchange")
			require.Equal(t, int32(1), chooserCalls.Load(), "as-is must not run a second dialer selection")
			require.Equal(t, int32(0), tcpForwarders.Load(), "as-is must not open a TCP transport")
			require.Equal(t, uint64(0), ctrl.dnsUdpTruncatedUpgrades.Load(), "no upgrade is attempted for as-is")
			require.Equal(t, uint64(0), ctrl.dnsUdpTruncatedUpgradeFailures.Load())
			require.Equal(t, uint64(1), ctrl.dnsTruncatedRepliesToClient.Load())
		})
	}
}

// TestAsIsNormalAnswerIsDeliveredUnchanged is the control case for the test
// above: outside the truncation signal nothing about as-is delivery moved, so
// the answer, its rcode and the transaction ID are the destination's.
func TestAsIsNormalAnswerIsDeliveredUnchanged(t *testing.T) {
	const queryName = "asis-normal-answer.test."

	var forwardCalls atomic.Int32
	installCorpusDnsForwarderFactory(t, func(_ *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		require.Equal(t, consts.L4ProtoStr_UDP, dialArg.l4proto)
		return &stubDnsForwarder{forward: func(_ context.Context, data []byte) (*dnsmessage.Msg, error) {
			forwardCalls.Add(1)
			var q dnsmessage.Msg
			require.NoError(t, q.Unpack(data))
			return dnsAResponseMsg(q.Question[0].Name, "198.51.100.90"), nil
		}}, nil
	})

	ctrl := newCorpusDnsController(t, truncatedTestConfig())
	setScopedBestDialerChooser(ctrl, func(_ context.Context, snapshot DnsRequestSnapshot, _ *componentdns.Upstream) (*dialArgument, error) {
		return &dialArgument{l4proto: consts.L4ProtoStr_UDP, ipversion: consts.IpVersionStr_4, bestTarget: snapshot.RealDst}, nil
	})

	writer := serveDNSQueryThroughListener(t, ctrl, "udp", queryName, 0x7a02)
	got := writer.Message()
	require.NotNil(t, got)
	require.Equal(t, dnsmessage.RcodeSuccess, got.Rcode)
	require.False(t, got.Truncated)
	require.Equal(t, "198.51.100.90", dnsAnswerIPv4(t, got))
	require.Equal(t, uint16(0x7a02), got.Id)
	require.Equal(t, int32(1), forwardCalls.Load())
}

// serveDNSQueryThroughListener runs one client query through the real DNS
// listener and returns the writer that captured the response, for both client
// transports.
func serveDNSQueryThroughListener(t *testing.T, ctrl *DnsController, transport, queryName string, queryID uint16) *dnsTransportResponseWriter {
	t.Helper()
	logger := newDNSListenerTestLogger()
	plane := &ControlPlane{
		ctx:                    context.Background(),
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{dnsController: ctrl},
	}
	listener, err := NewDNSListener(logger, "127.0.0.1:5353", plane)
	require.NoError(t, err)
	plane.dnsListener = listener

	query := new(dnsmessage.Msg)
	query.SetQuestion(queryName, dnsmessage.TypeA)
	query.Id = queryID
	var writer *dnsTransportResponseWriter
	if transport == "tcp" {
		writer = &dnsTransportResponseWriter{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}}
	} else {
		writer = &dnsTransportResponseWriter{addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}}
	}
	(&dnsHandler{listener: listener, log: logger}).ServeDNS(writer, query)
	return writer
}
