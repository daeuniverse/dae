package protocol

import "net"

func TCPAddrToUDPAddr(addr *net.TCPAddr) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   addr.IP,
		Port: addr.Port,
		Zone: addr.Zone,
	}
}
