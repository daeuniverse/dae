package control

import (
	"context"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// A singleflight leader must re-check the cache before going upstream: another
// request may have populated the entry between the outer miss and the moment
// this leader started resolving, and resolving again would send a duplicate
// query for an answer that is already cached.
func TestResolveForSingleflightRechecksCache(t *testing.T) {
	controller := newTestDnsController()
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 0x4321

	cache := &DnsCache{
		Answer: []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		}},
		Deadline: time.Now().Add(time.Minute),
	}
	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		t.Fatalf("PrepackResponse() error = %v", err)
	}
	const cacheKey = "singleflight-cache-key"
	// Publish through the controller's store so the base-key index stays in sync.
	controller.storeDnsCache(cacheKey, cache)

	response, err := controller.resolveForSingleflight(
		context.Background(),
		query,
		&udpRequest{},
		0,
		nil,
		cacheKey,
	)
	if err != nil {
		t.Fatalf("resolveForSingleflight() error = %v", err)
	}
	if response == nil {
		t.Fatal("resolveForSingleflight() returned no DNS response")
		return
	}
	if response.Id != query.Id {
		t.Fatalf("response ID = %d, want %d", response.Id, query.Id)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(response.Answer))
	}
}

func TestDnsController_NewWorkContext_HonorsLifecycleContext(t *testing.T) {
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	ctrl := setTestDnsControllerRuntime(&DnsController{}, func(rt *dnsControllerRuntimeState) {
		rt.lifecycleCtx = lifecycleCtx
	})

	workCtx, workCancel := ctrl.newWorkContext(time.Second)
	defer workCancel()

	select {
	case <-workCtx.Done():
		t.Fatal("work context should stay alive while lifecycle is active")
	default:
	}

	lifecycleCancel()

	select {
	case <-workCtx.Done():
		if workCtx.Err() != context.Canceled {
			t.Fatalf("work context err = %v, want context.Canceled", workCtx.Err())
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for work context to honor lifecycle cancellation")
	}
}
