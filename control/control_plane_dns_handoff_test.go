package control

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestChooseDialTargetUsesDNSHandoff(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	controller, err := NewDnsController(nil, &DnsControllerOption{Log: log})
	if err != nil {
		t.Fatalf("create DNS controller: %v", err)
	}
	defer func() { _ = controller.Close() }()

	const domain = "example.com"
	dst := netip.MustParseAddrPort("203.0.113.1:443")
	controller.rememberDnsKnowledge(
		controller.cacheKey(domain, dnsmessage.TypeA),
		time.Now().Add(time.Minute),
	)

	controlPlane := &ControlPlane{
		log: log,
		controlPlaneGenerationState: controlPlaneGenerationState{
			dialMode: consts.DialMode_Domain,
		},
	}
	controlPlane.dnsHandoffController.Store(controller)

	dialTarget, shouldReroute, dialIP := controlPlane.ChooseDialTarget(
		consts.OutboundIndex(100),
		dst,
		domain,
	)

	if dialTarget != "example.com:443" {
		t.Fatalf("dial target = %q, want %q", dialTarget, "example.com:443")
	}
	if !shouldReroute {
		t.Fatal("expected handoff DNS knowledge to enable rerouting")
	}
	if dialIP {
		t.Fatal("expected domain dial target, got IP dial mode")
	}
}
