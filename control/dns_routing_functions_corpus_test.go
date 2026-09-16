/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// TestPhase0DnsRoutingFunctionsCorpus_LegacyBaseline exercises DNS routing
// functions through DnsController instead of calling request/response matchers
// directly. The selected request upstream and response-routing disposition are
// observable through the deterministic forwarder and captured client response.
func TestPhase0DnsRoutingFunctionsCorpus_LegacyBaseline(t *testing.T) {
	t.Run("request_qtype_selects_named_upstream", func(t *testing.T) {
		ctrl := newCorpusControllerWithDefaultChooser(t, &config.Dns{
			Upstream: []config.KeyableString{"typed:udp://192.0.2.53:53"},
			Routing: config.DnsRouting{
				Request: config.DnsRequestRouting{
					Rules: []*config_parser.RoutingRule{
						phase0DnsRoutingRule(consts.Function_QType, "typed", &config_parser.Param{Val: "AAAA"}),
					},
					Fallback: config.FunctionOrString("asis"),
				},
				Response: config.DnsResponseRouting{Fallback: config.FunctionOrString("accept")},
			},
		})

		var selectedHost string
		installCorpusDnsForwarderFactory(t, func(upstream *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			if upstream == nil {
				return nil, fmt.Errorf("qtype rule selected as-is upstream")
			}
			selectedHost = upstream.Hostname
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				return phase0DnsAAAAResponseMsg("request-qtype.test.", "2001:db8::53"), nil
			}}, nil
		})

		response := replayPhase0DnsRoutingQuery(t, ctrl, "request-qtype.test.", dnsmessage.TypeAAAA)
		if selectedHost != "192.0.2.53" {
			t.Fatalf("request qtype selected upstream host %q, want %q", selectedHost, "192.0.2.53")
		}
		if len(response.Answer) != 1 {
			t.Fatalf("request qtype response answers = %d, want 1", len(response.Answer))
		}
	})

	t.Run("response_qname_rejects_matching_answer", func(t *testing.T) {
		ctrl := newCorpusControllerWithDefaultChooser(t, &config.Dns{
			Upstream: []config.KeyableString{"primary:udp://192.0.2.53:53"},
			Routing: config.DnsRouting{
				Request: config.DnsRequestRouting{Fallback: config.FunctionOrString("primary")},
				Response: config.DnsResponseRouting{
					Rules: []*config_parser.RoutingRule{
						phase0DnsRoutingRule(consts.Function_QName, "reject", &config_parser.Param{
							Key: string(consts.RoutingDomainKey_Full),
							Val: "response-qname.test",
						}),
					},
					Fallback: config.FunctionOrString("accept"),
				},
			},
		})

		installCorpusDnsForwarderFactory(t, phase0DnsRoutingAForwarder("response-qname.test.", "203.0.113.53"))
		response := replayPhase0DnsRoutingQuery(t, ctrl, "response-qname.test.", dnsmessage.TypeA)
		if len(response.Answer) != 0 {
			t.Fatalf("response qname reject returned %d answers, want 0", len(response.Answer))
		}
	})

	t.Run("response_qtype_rejects_matching_answer", func(t *testing.T) {
		ctrl := newCorpusControllerWithDefaultChooser(t, &config.Dns{
			Upstream: []config.KeyableString{"primary:udp://192.0.2.53:53"},
			Routing: config.DnsRouting{
				Request: config.DnsRequestRouting{Fallback: config.FunctionOrString("primary")},
				Response: config.DnsResponseRouting{
					Rules: []*config_parser.RoutingRule{
						phase0DnsRoutingRule(consts.Function_QType, "reject", &config_parser.Param{Val: "AAAA"}),
					},
					Fallback: config.FunctionOrString("accept"),
				},
			},
		})

		installCorpusDnsForwarderFactory(t, func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				return phase0DnsAAAAResponseMsg("response-qtype.test.", "2001:db8::54"), nil
			}}, nil
		})

		response := replayPhase0DnsRoutingQuery(t, ctrl, "response-qtype.test.", dnsmessage.TypeAAAA)
		if len(response.Answer) != 0 {
			t.Fatalf("response qtype reject returned %d answers, want 0", len(response.Answer))
		}
	})

	t.Run("response_ip_rejects_matching_answer", func(t *testing.T) {
		ctrl := newCorpusControllerWithDefaultChooser(t, &config.Dns{
			Upstream: []config.KeyableString{"primary:udp://192.0.2.53:53"},
			Routing: config.DnsRouting{
				Request: config.DnsRequestRouting{Fallback: config.FunctionOrString("primary")},
				Response: config.DnsResponseRouting{
					Rules: []*config_parser.RoutingRule{
						phase0DnsRoutingRule(consts.Function_Ip, "reject", &config_parser.Param{Val: "203.0.113.0/24"}),
					},
					Fallback: config.FunctionOrString("accept"),
				},
			},
		})

		installCorpusDnsForwarderFactory(t, phase0DnsRoutingAForwarder("response-ip.test.", "203.0.113.54"))
		response := replayPhase0DnsRoutingQuery(t, ctrl, "response-ip.test.", dnsmessage.TypeA)
		if len(response.Answer) != 0 {
			t.Fatalf("response ip reject returned %d answers, want 0", len(response.Answer))
		}
	})

	t.Run("response_upstream_resends_via_selected_upstream", func(t *testing.T) {
		ctrl := newCorpusControllerWithDefaultChooser(t, &config.Dns{
			Upstream: []config.KeyableString{
				"primary:udp://192.0.2.53:53",
				"secondary:udp://192.0.2.54:53",
			},
			Routing: config.DnsRouting{
				Request: config.DnsRequestRouting{Fallback: config.FunctionOrString("primary")},
				Response: config.DnsResponseRouting{
					Rules: []*config_parser.RoutingRule{
						phase0DnsRoutingRule(consts.Function_Upstream, "secondary", &config_parser.Param{Val: "primary"}),
					},
					Fallback: config.FunctionOrString("accept"),
				},
			},
		})

		var calls []string
		installCorpusDnsForwarderFactory(t, func(upstream *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			if upstream == nil {
				return nil, fmt.Errorf("response upstream rule selected as-is upstream")
			}
			calls = append(calls, upstream.Hostname)
			switch upstream.Hostname {
			case "192.0.2.53":
				return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
					return dnsAResponseMsg("response-upstream.test.", "203.0.113.55"), nil
				}}, nil
			case "192.0.2.54":
				return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
					return dnsAResponseMsg("response-upstream.test.", "198.51.100.55"), nil
				}}, nil
			default:
				return nil, fmt.Errorf("unexpected upstream host %q", upstream.Hostname)
			}
		})

		response := replayPhase0DnsRoutingQuery(t, ctrl, "response-upstream.test.", dnsmessage.TypeA)
		if len(calls) != 2 || calls[0] != "192.0.2.53" || calls[1] != "192.0.2.54" {
			t.Fatalf("response upstream forward sequence = %v, want [192.0.2.53 192.0.2.54]", calls)
		}
		if got := dnsAnswerIPv4(t, response); got != "198.51.100.55" {
			t.Fatalf("response upstream final answer = %s, want %s", got, "198.51.100.55")
		}
	})
}

func replayPhase0DnsRoutingQuery(t *testing.T, ctrl *DnsController, name string, qtype uint16) *dnsmessage.Msg {
	t.Helper()

	query := new(dnsmessage.Msg)
	query.SetQuestion(name, qtype)
	writer := &captureResponseWriter{}
	if err := ctrl.HandleWithResponseWriter_(context.Background(), query, defaultUdpRequest(), writer); err != nil {
		t.Fatalf("HandleWithResponseWriter_(%q, %d): %v", name, qtype, err)
	}
	response := writer.Message()
	if response == nil {
		t.Fatalf("HandleWithResponseWriter_(%q, %d) did not write a response", name, qtype)
	}
	return response
}

func phase0DnsRoutingRule(function, outbound string, params ...*config_parser.Param) *config_parser.RoutingRule {
	return &config_parser.RoutingRule{
		AndFunctions: []*config_parser.Function{{
			Name:   function,
			Params: params,
		}},
		Outbound: config_parser.Function{Name: outbound},
	}
}

func phase0DnsRoutingAForwarder(name, address string) func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
	return func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			return dnsAResponseMsg(name, address), nil
		}}, nil
	}
}

func phase0DnsAAAAResponseMsg(name, address string) *dnsmessage.Msg {
	msg := new(dnsmessage.Msg)
	msg.SetReply(&dnsmessage.Msg{})
	msg.SetQuestion(name, dnsmessage.TypeAAAA)
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.AAAA{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName(name),
				Rrtype: dnsmessage.TypeAAAA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			AAAA: net.ParseIP(address).To16(),
		},
	}
	return msg
}
