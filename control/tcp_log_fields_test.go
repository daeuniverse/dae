package control

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	outbounddialer "github.com/daeuniverse/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func newTestDialerGroup(name string) *outbound.DialerGroup {
	log := logrus.New()
	return &outbound.DialerGroup{
		Name: name,
		Dialers: []*dialer.Dialer{
			dialer.NewDialer(nil, &dialer.GlobalOption{Log: log}, dialer.InstanceOption{}, &dialer.Property{Property: outbounddialer.Property{Name: "unit-test-dialer"}}),
		},
	}
}

func TestBuildTCPLinkLogFields_MarksEBPFOffload(t *testing.T) {
	fields := buildTCPLinkLogFields(
		&proxyDialResult{
			Outbound: func() *outbound.DialerGroup {
				g := newTestDialerGroup("socks5-out")
				g.SetSelectionPolicy(outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed})
				return g
			}(),
			Dialer:          dialer.NewDialer(nil, &dialer.GlobalOption{Log: logrus.New()}, dialer.InstanceOption{}, &dialer.Property{Property: outbounddialer.Property{Name: "unit-test-dialer"}}),
			OrigNetworkType: "tcp4",
		},
		&proxyDialParam{
			Dscp:        46,
			Mac:         [6]uint8{0, 1, 2, 3, 4, 5},
			ProcessName: [16]uint8{'c', 'u', 'r', 'l'},
		},
		netip.MustParseAddrPort("93.184.216.34:443"),
		"example.com",
		true,
		true,
		"",
	)

	if got, ok := fields["ebpf_offload"].(bool); !ok || !got {
		t.Fatalf("expected ebpf_offload=true, got %#v", fields["ebpf_offload"])
	}
	if got := fields["sniffed"]; got != "example.com" {
		t.Fatalf("expected sniffed domain preserved, got %#v", got)
	}
	if _, ok := fields["relay_mode"]; ok {
		t.Fatal("did not expect relay_mode field")
	}
	if _, ok := fields["ebpf_offload_reason"]; ok {
		t.Fatal("did not expect ebpf_offload_reason on successful offload")
	}
}

func TestBuildTCPLinkLogFields_MarksUserspaceRelay(t *testing.T) {
	fields := buildTCPLinkLogFields(
		&proxyDialResult{
			Outbound: func() *outbound.DialerGroup {
				g := newTestDialerGroup("socks5-out")
				g.SetSelectionPolicy(outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed})
				return g
			}(),
			Dialer:          dialer.NewDialer(nil, &dialer.GlobalOption{Log: logrus.New()}, dialer.InstanceOption{}, &dialer.Property{Property: outbounddialer.Property{Name: "unit-test-dialer"}}),
			OrigNetworkType: "tcp6",
		},
		&proxyDialParam{},
		netip.MustParseAddrPort("[2606:2800:220:1:248:1893:25c8:1946]:443"),
		"",
		true,
		false,
		"right connection cannot be unwrapped to plain tcp",
	)

	if got, ok := fields["ebpf_offload"].(bool); !ok || got {
		t.Fatalf("expected ebpf_offload=false, got %#v", fields["ebpf_offload"])
	}
	if _, ok := fields["ebpf_offload"]; !ok {
		t.Fatal("expected ebpf_offload field to exist")
	}
	if _, ok := fields["relay_mode"]; ok {
		t.Fatal("did not expect relay_mode field")
	}
	if got := fields["ebpf_offload_reason"]; got != "right connection cannot be unwrapped to plain tcp" {
		t.Fatalf("expected ebpf_offload_reason to be preserved, got %#v", got)
	}
}

func TestBuildTCPLinkLogFields_SkipsOffloadFieldsForNonOffloadableOutbound(t *testing.T) {
	fields := buildTCPLinkLogFields(
		&proxyDialResult{
			Outbound: func() *outbound.DialerGroup {
				g := newTestDialerGroup("ws-out")
				g.SetSelectionPolicy(outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed})
				return g
			}(),
			Dialer:          dialer.NewDialer(nil, &dialer.GlobalOption{Log: logrus.New()}, dialer.InstanceOption{}, &dialer.Property{Property: outbounddialer.Property{Name: "unit-test-dialer"}}),
			OrigNetworkType: "tcp4",
		},
		&proxyDialParam{},
		netip.MustParseAddrPort("93.184.216.34:443"),
		"",
		false,
		false,
		"right connection cannot be unwrapped to plain tcp",
	)

	if _, ok := fields["ebpf_offload"]; ok {
		t.Fatal("did not expect ebpf_offload field for non-offloadable outbound")
	}
	if _, ok := fields["relay_mode"]; ok {
		t.Fatal("did not expect relay_mode field for non-offloadable outbound")
	}
	if _, ok := fields["ebpf_offload_reason"]; ok {
		t.Fatal("did not expect ebpf_offload_reason field for non-offloadable outbound")
	}
	if got := fields["outbound"]; got != "ws-out" {
		t.Fatalf("expected base link fields to remain, got outbound=%#v", got)
	}
}

func TestTCPRelayOffloadReason_StripsSentinelPrefix(t *testing.T) {
	err := fmt.Errorf("%w: left is not a plain *net.TCPConn", errTCPRelayOffloadUnavailable)
	if got := tcpRelayOffloadReason(err); got != "left is not a plain *net.TCPConn" {
		t.Fatalf("unexpected normalized reason: %q", got)
	}
}
