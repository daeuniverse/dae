package control

import (
	"context"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func TestMsgCapturer_WriteMsg(t *testing.T) {
	capturer := &msgCapturer{}

	if capturer.msg != nil {
		t.Fatal("initial msg should be nil")
	}

	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	msg.SetReply(msg)
	msg.Answer = append(msg.Answer, &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "example.com.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    300,
		},
		A: []byte{93, 184, 216, 34},
	})

	if err := capturer.WriteMsg(msg); err != nil {
		t.Fatalf("WriteMsg failed: %v", err)
	}
	if capturer.msg == nil {
		t.Fatal("msg should be captured, but it's nil")
	}
	if len(capturer.msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(capturer.msg.Answer))
	}
}

func TestMsgCapturer_NilWhenNotWritten(t *testing.T) {
	capturer := &msgCapturer{}

	if capturer.msg != nil {
		t.Fatal("msg should be nil when WriteMsg is never called")
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
