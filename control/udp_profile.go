/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"time"

	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
)

type UdpLifecycleKind uint8

const (
	UdpLifecycleKindDnsTransactional UdpLifecycleKind = iota + 1
	UdpLifecycleKindDataSession
)

type UdpLifecycleProfile struct {
	Kind                       UdpLifecycleKind
	HealthDomain               componentdialer.UdpHealthDomain
	StickyAfterReply           bool
	PromoteOnReply             bool
	RetireOnNormalClose        bool
	DiscardPooledConnOnTimeout bool
	PooledConnIdleTTL          time.Duration
}

func newDnsLifecycleProfile(d *componentdialer.Dialer) UdpLifecycleProfile {
	profile := UdpLifecycleProfile{
		Kind:                       UdpLifecycleKindDnsTransactional,
		HealthDomain:               componentdialer.UdpHealthDomainDns,
		PooledConnIdleTTL:          dnsUdpDirectPoolMaxIdleTime,
		DiscardPooledConnOnTimeout: false,
	}
	if isProxyBackedDialer(d) {
		profile.PooledConnIdleTTL = dnsUdpProxyPoolMaxIdleTime
		profile.DiscardPooledConnOnTimeout = true
	}
	return profile
}

func newDataSessionLifecycleProfile(d *componentdialer.Dialer) UdpLifecycleProfile {
	return UdpLifecycleProfile{
		Kind:                UdpLifecycleKindDataSession,
		HealthDomain:        componentdialer.UdpHealthDomainData,
		StickyAfterReply:    true,
		PromoteOnReply:      true,
		RetireOnNormalClose: isProxyBackedDialer(d),
	}
}
