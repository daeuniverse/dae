package protocol

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
)

type Metadata struct {
	Type     MetadataType
	Hostname string
	Port     uint16
	// Cmd is valid only if Type is MetadataTypeMsg.
	Cmd      MetadataCmd
	Cipher   string
	IsClient bool
}

func (m *Metadata) DomainIpMapping(cache *sync.Map) (addrPort netip.AddrPort, err error) {
	if m.Type == MetadataTypeDomain {
		if _addr, ok := cache.Load(m.Hostname); ok {
			addrPort = netip.AddrPortFrom(_addr.(netip.Addr), m.Port)
		} else {
			uAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(m.Hostname, strconv.Itoa(int(m.Port))))
			if err != nil {
				return netip.AddrPort{}, err
			}
			addrPort = uAddr.AddrPort()
			if _addr, ok = cache.LoadOrStore(m.Hostname, addrPort.Addr()); ok {
				addrPort = netip.AddrPortFrom(_addr.(netip.Addr), m.Port)
			}
		}
	} else {
		if addrPort, err = m.AddrPort(); err != nil {
			return netip.AddrPort{}, fmt.Errorf("ReadFrom AddrPort: %w", err)
		}
	}
	return addrPort, nil
}

type MetadataCmd uint8

const (
	MetadataCmdPing MetadataCmd = iota
	MetadataCmdSyncPassages
	MetadataCmdResponse
)

type MetadataType int

const (
	MetadataTypeIPv4 MetadataType = iota
	MetadataTypeIPv6
	MetadataTypeDomain
	MetadataTypeMsg
	MetadataTypeInvalid
)

func ParseMetadata(tgt string) (mdata Metadata, err error) {
	host, strPort, err := net.SplitHostPort(tgt)
	if err != nil {
		return mdata, fmt.Errorf("SplitHostPort: %w", err)
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return mdata, fmt.Errorf("failed to parse port: %w", err)
	}
	tgtIP, err := netip.ParseAddr(host)
	var typ MetadataType
	if err != nil {
		typ = MetadataTypeDomain
	} else if tgtIP.Is4() {
		typ = MetadataTypeIPv4
	} else {
		typ = MetadataTypeIPv6
	}
	return Metadata{
		Type:     typ,
		Hostname: host,
		Port:     uint16(port),
	}, nil
}

func (m *Metadata) AddrPort() (netip.AddrPort, error) {
	switch m.Type {
	case MetadataTypeIPv4, MetadataTypeIPv6:
		ip, err := netip.ParseAddr(m.Hostname)
		if err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(ip, m.Port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("bad metadata type: %v; should be ip", m.Type)
	}
}
