/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/daedns"
	D "github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/anytls"
	"github.com/daeuniverse/outbound/netproxy"
	_ "github.com/daeuniverse/outbound/protocol/anytls"
	"github.com/sirupsen/logrus"
	"go.uber.org/goleak"
)

type registrationOwnedDialer struct {
	closes int
}

func (*registrationOwnedDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, fmt.Errorf("unexpected network access")
}

func (d *registrationOwnedDialer) Close() error {
	d.closes++
	return nil
}

func TestRegistrationClosesEveryOwnedDialer(t *testing.T) {
	for i, tc := range []struct {
		name    string
		address string
		daeDNS  bool
		failAt  int
	}{
		{name: "ip", address: "203.0.113.1:443"},
		{name: "sticky", address: "example.com:443"},
		{name: "dns", address: "203.0.113.1:443", daeDNS: true},
		{name: "dns_and_sticky", address: "example.com:443", daeDNS: true},
		{name: "sticky_failure", address: "example.com:443", failAt: 2},
		{name: "dns_failure", address: "example.com:443", daeDNS: true, failAt: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var created []*registrationOwnedDialer
			calls := 0
			scheme := fmt.Sprintf("registration-ownership-%d", i)
			D.FromLinkRegister(scheme, func(*D.ExtraOption, netproxy.Dialer, string) (netproxy.Dialer, *D.Property, error) {
				calls++
				if calls == tc.failAt {
					return nil, nil, fmt.Errorf("construction failed")
				}
				d := &registrationOwnedDialer{}
				created = append(created, d)
				return d, &D.Property{Name: tc.name, Address: tc.address}, nil
			})
			option := &GlobalOption{Log: logrus.New(), CheckInterval: time.Minute}
			if tc.daeDNS {
				option.DaeDNS = &daedns.Router{}
			}
			d, err := NewFromLinkContext(context.Background(), option, InstanceOption{DisableCheck: true}, scheme+"://node", "")
			if tc.failAt != 0 {
				if err == nil {
					if d != nil {
						_ = d.Close()
					}
					t.Fatal("expected construction failure")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := d.Close(); err != nil {
					t.Fatal(err)
				}
				if err := d.Close(); err != nil {
					t.Fatal(err)
				}
			}
			for index, owned := range created {
				if owned.closes != 1 {
					t.Errorf("constructed dialer %d closed %d times, want exactly once", index, owned.closes)
				}
			}
		})
	}
}

func TestAnyTLSRegistrationDoesNotLeakJanitors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		link   string
		daeDNS bool
	}{
		{name: "ip", link: "anytls://pass@203.0.113.1:443"},
		{name: "domain", link: "anytls://pass@example.com:443"},
		{name: "domain_dns", link: "anytls://pass@example.com:443", daeDNS: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
			option := &GlobalOption{Log: logrus.New(), CheckInterval: time.Minute}
			if tc.daeDNS {
				option.DaeDNS = &daedns.Router{}
			}
			d, err := NewFromLinkContext(context.Background(), option, InstanceOption{DisableCheck: true}, tc.link, "")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = d.Close() }()
		})
	}
}
