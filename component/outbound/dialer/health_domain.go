/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import "github.com/daeuniverse/dae/common/consts"

type HealthDomain uint8

const (
	HealthDomainUnset HealthDomain = iota
	HealthDomainTCP
	HealthDomainDnsUDP
	HealthDomainDataUDP
)

func (d HealthDomain) String() string {
	switch d {
	case HealthDomainTCP:
		return "tcp"
	case HealthDomainDnsUDP:
		return "dns_udp"
	case HealthDomainDataUDP:
		return "data_udp"
	default:
		return "unknown"
	}
}

type HealthKey struct {
	Domain    HealthDomain
	IpVersion consts.IpVersionStr
}

func (t *NetworkType) HealthDomain() HealthDomain {
	if t == nil {
		return HealthDomainUnset
	}
	if t.L4Proto == consts.L4ProtoStr_TCP {
		return HealthDomainTCP
	}
	switch t.EffectiveUdpHealthDomain() {
	case UdpHealthDomainDns:
		return HealthDomainDnsUDP
	case UdpHealthDomainData:
		return HealthDomainDataUDP
	default:
		return HealthDomainUnset
	}
}

func (t *NetworkType) HealthKey() HealthKey {
	if t == nil {
		return HealthKey{}
	}
	return HealthKey{
		Domain:    t.HealthDomain(),
		IpVersion: t.IpVersion,
	}
}

func (k HealthKey) CollectionIndex() int {
	switch k.Domain {
	case HealthDomainTCP:
		switch k.IpVersion {
		case consts.IpVersionStr_4:
			return IdxTcp4
		case consts.IpVersionStr_6:
			return IdxTcp6
		}
	case HealthDomainDnsUDP:
		switch k.IpVersion {
		case consts.IpVersionStr_4:
			return IdxDnsUdp4
		case consts.IpVersionStr_6:
			return IdxDnsUdp6
		}
	case HealthDomainDataUDP:
		switch k.IpVersion {
		case consts.IpVersionStr_4:
			return IdxUdp4
		case consts.IpVersionStr_6:
			return IdxUdp6
		}
	}
	panic("invalid health key")
}

func (k HealthKey) NetworkType() *NetworkType {
	switch k.Domain {
	case HealthDomainTCP:
		return &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: k.IpVersion,
		}
	case HealthDomainDnsUDP:
		return &NetworkType{
			L4Proto:         consts.L4ProtoStr_UDP,
			IpVersion:       k.IpVersion,
			IsDns:           true,
			UdpHealthDomain: UdpHealthDomainDns,
		}
	case HealthDomainDataUDP:
		return &NetworkType{
			L4Proto:         consts.L4ProtoStr_UDP,
			IpVersion:       k.IpVersion,
			UdpHealthDomain: UdpHealthDomainData,
		}
	default:
		return nil
	}
}

func HealthKeyFromCollectionIndex(idx int) (HealthKey, bool) {
	switch idx {
	case IdxDnsUdp4:
		return HealthKey{Domain: HealthDomainDnsUDP, IpVersion: consts.IpVersionStr_4}, true
	case IdxDnsUdp6:
		return HealthKey{Domain: HealthDomainDnsUDP, IpVersion: consts.IpVersionStr_6}, true
	case IdxTcp4:
		return HealthKey{Domain: HealthDomainTCP, IpVersion: consts.IpVersionStr_4}, true
	case IdxTcp6:
		return HealthKey{Domain: HealthDomainTCP, IpVersion: consts.IpVersionStr_6}, true
	case IdxUdp4:
		return HealthKey{Domain: HealthDomainDataUDP, IpVersion: consts.IpVersionStr_4}, true
	case IdxUdp6:
		return HealthKey{Domain: HealthDomainDataUDP, IpVersion: consts.IpVersionStr_6}, true
	default:
		return HealthKey{}, false
	}
}

func StandardHealthKeys() [6]HealthKey {
	return [6]HealthKey{
		{Domain: HealthDomainDnsUDP, IpVersion: consts.IpVersionStr_4},
		{Domain: HealthDomainDnsUDP, IpVersion: consts.IpVersionStr_6},
		{Domain: HealthDomainTCP, IpVersion: consts.IpVersionStr_4},
		{Domain: HealthDomainTCP, IpVersion: consts.IpVersionStr_6},
		{Domain: HealthDomainDataUDP, IpVersion: consts.IpVersionStr_4},
		{Domain: HealthDomainDataUDP, IpVersion: consts.IpVersionStr_6},
	}
}
