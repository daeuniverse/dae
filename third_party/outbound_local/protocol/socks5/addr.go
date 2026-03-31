package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/outbound/pool"
)

type AddressType uint8

// Address type constants for Shadowsocks protocol
const (
	AddressTypeIPv4   AddressType = 1
	AddressTypeDomain AddressType = 3
	AddressTypeIPv6   AddressType = 4
)

var (
	ErrInvalidAddress = fmt.Errorf("invalid address")
)

// AddressInfo represents decoded address information
type AddressInfo struct {
	Type     AddressType
	Hostname string
	IP       netip.Addr
	Port     uint16
}

func WriteAddr(addr string, buf *bytes.Buffer) error {
	addressInfo, err := AddressFromString(addr)
	if err != nil {
		return err
	}
	return WriteAddrInfo(addressInfo, buf)
}

// WriteAddrInfo writes address information to writer
func WriteAddrInfo(addr *AddressInfo, w io.Writer) error {
	var typeBuf [1]byte
	typeBuf[0] = byte(addr.Type)
	if _, err := w.Write(typeBuf[:]); err != nil {
		return err
	}

	switch addr.Type {
	case AddressTypeIPv4, AddressTypeIPv6:
		if _, err := w.Write(addr.IP.AsSlice()); err != nil {
			return err
		}
		var portBuf [2]byte
		binary.BigEndian.PutUint16(portBuf[:], addr.Port)
		_, err := w.Write(portBuf[:])
		return err
	case AddressTypeDomain:
		lenDN := len(addr.Hostname)
		if lenDN > 255 {
			return fmt.Errorf("domain name too long: %d bytes", lenDN)
		}
		var lenBuf [1]byte
		lenBuf[0] = uint8(lenDN)
		if _, err := w.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := io.WriteString(w, addr.Hostname); err != nil {
			return err
		}
		var portBuf [2]byte
		binary.BigEndian.PutUint16(portBuf[:], addr.Port)
		_, err := w.Write(portBuf[:])
		return err
	default:
		return fmt.Errorf("unsupported address type: %v", addr.Type)
	}
}

func ReadAddr(data io.Reader) (net.Addr, error) {
	addressInfo, err := ReadAddrInfo(data)
	if err != nil {
		return nil, err
	}

	// Create address object (only support IP addresses for UDP)
	switch addressInfo.Type {
	case AddressTypeIPv4, AddressTypeIPv6:
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(addressInfo.IP, addressInfo.Port)), nil
	default:
		return nil, fmt.Errorf("unsupported address type for UDP: %v", addressInfo.Type)
	}
}

// ReadAddr reads address from buffer
func ReadAddrInfo(data io.Reader) (*AddressInfo, error) {
	var typ uint8
	if err := binary.Read(data, binary.BigEndian, &typ); err != nil {
		return nil, fmt.Errorf("%w: too short", ErrInvalidAddress)
	}

	info := &AddressInfo{Type: AddressType(typ)}

	switch info.Type {
	case AddressTypeIPv4:
		ip := pool.Get(4)
		defer pool.Put(ip)
		if _, err := data.Read(ip); err != nil {
			return nil, fmt.Errorf("failed to read IP: %w", err)
		}
		info.IP = netip.AddrFrom4([4]byte(ip))
		if err := binary.Read(data, binary.BigEndian, &info.Port); err != nil {
			return nil, fmt.Errorf("failed to read port: %w", err)
		}
	case AddressTypeIPv6:
		ip := pool.Get(16)
		defer pool.Put(ip)
		if _, err := data.Read(ip); err != nil {
			return nil, fmt.Errorf("failed to read IP: %w", err)
		}
		info.IP = netip.AddrFrom16([16]byte(ip))
		if err := binary.Read(data, binary.BigEndian, &info.Port); err != nil {
			return nil, fmt.Errorf("failed to read port: %w", err)
		}
	case AddressTypeDomain:
		var domainLen uint8
		if err := binary.Read(data, binary.BigEndian, &domainLen); err != nil {
			return nil, fmt.Errorf("failed to read domain length: %w", err)
		}
		domain := pool.Get(int(domainLen))
		defer pool.Put(domain)
		if _, err := data.Read(domain); err != nil {
			return nil, fmt.Errorf("failed to read domain: %w", err)
		}
		info.Hostname = string(domain)
		if err := binary.Read(data, binary.BigEndian, &info.Port); err != nil {
			return nil, fmt.Errorf("failed to read port: %w", err)
		}
	default:
		return nil, fmt.Errorf("%w: invalid type: %v", ErrInvalidAddress, info.Type)
	}
	return info, nil
}

func AddressFromString(addr string) (*AddressInfo, error) {
	hostname, port_, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(port_, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", port_)
	}

	info := &AddressInfo{Port: uint16(port)}

	ip, err := netip.ParseAddr(hostname)
	if err != nil {
		info.Type = AddressTypeDomain
		info.Hostname = hostname
	} else {
		info.IP = ip
		if ip.Is4() {
			info.Type = AddressTypeIPv4
		} else {
			info.Type = AddressTypeIPv6
		}
	}
	return info, nil
}
