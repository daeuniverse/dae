package control

import (
	"context"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestDnsController_ConcurrencyLimit(t *testing.T) {
	// Initialize DnsController with a limit of 1
	opt := &DnsControllerOption{
		Log:              logrus.New(),
		ConcurrencyLimit: 1,
		IpVersionPrefer:  int(IpVersionPrefer_4),
	}
	// We can pass nil for routing because we expect to hit the limit before routing is accessed.
	ctrl, err := NewDnsController(nil, opt)
	if err != nil {
		t.Fatalf("Failed to create DnsController: %v", err)
	}

	// Manually fill the semaphore
	select {
	case ctrl.concurrencyLimiter <- struct{}{}:
	default:
		t.Fatal("Failed to fill semaphore")
	}

	// Create a dummy DNS message
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	msg.RecursionDesired = true

	// Create a dummy request
	req := &udpRequest{
		routingResult: &bpfRoutingResult{
			Outbound: uint8(consts.OutboundControlPlaneRouting),
		},
	}

	// Call HandleWithResponseWriter_
	// It should fail immediately because the semaphore is full
	err = ctrl.HandleWithResponseWriter_(context.Background(), msg, req, nil)

	if err == nil {
		t.Fatal("Expected error due to concurrency limit, got nil")
	}

	if !strings.Contains(err.Error(), "concurrency limit exceeded") {
		t.Errorf("Expected 'concurrency limit exceeded' error, got: %v", err)
	}
}
