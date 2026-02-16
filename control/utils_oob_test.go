/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestRetrieveOriginalDest_IPv4(t *testing.T) {
	expected := netip.MustParseAddrPort("1.2.3.4:443")
	oob := buildOrigDstCmsgIPv4(expected)
	got := RetrieveOriginalDest(oob)
	require.Equal(t, expected, got)
}

func TestRetrieveOriginalDest_IPv6(t *testing.T) {
	expected := netip.MustParseAddrPort("[2001:db8::1]:853")
	oob := buildOrigDstCmsgIPv6(expected)
	got := RetrieveOriginalDest(oob)
	require.Equal(t, expected, got)
}

func TestRetrieveOriginalDest_SkipUnknownCmsg(t *testing.T) {
	expected := netip.MustParseAddrPort("9.9.9.9:53")
	oob := append(buildDummyCmsg(), buildOrigDstCmsgIPv4(expected)...)
	got := RetrieveOriginalDest(oob)
	require.Equal(t, expected, got)
}

func TestRetrieveOriginalDest_Malformed(t *testing.T) {
	got := RetrieveOriginalDest([]byte{1, 2, 3})
	require.False(t, got.IsValid())
}

func buildDummyCmsg() []byte {
	oob := make([]byte, unix.CmsgSpace(4))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = syscall.SOL_SOCKET
	h.Type = 0
	h.SetLen(unix.CmsgLen(4))
	binary.NativeEndian.PutUint32(oob[unix.CmsgSpace(0):unix.CmsgSpace(0)+4], 0x11223344)
	return oob
}

func buildOrigDstCmsgIPv4(ap netip.AddrPort) []byte {
	oob := make([]byte, unix.CmsgSpace(unix.SizeofSockaddrInet4))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = syscall.SOL_IP
	h.Type = syscall.IP_RECVORIGDSTADDR
	h.SetLen(unix.CmsgLen(unix.SizeofSockaddrInet4))

	data := oob[unix.CmsgSpace(0) : unix.CmsgSpace(0)+unix.SizeofSockaddrInet4]
	binary.NativeEndian.PutUint16(data[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(data[2:4], ap.Port())
	ip := ap.Addr().As4()
	copy(data[4:8], ip[:])
	return oob
}

func buildOrigDstCmsgIPv6(ap netip.AddrPort) []byte {
	oob := make([]byte, unix.CmsgSpace(unix.SizeofSockaddrInet6))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = syscall.SOL_IPV6
	h.Type = unix.IPV6_RECVORIGDSTADDR
	h.SetLen(unix.CmsgLen(unix.SizeofSockaddrInet6))

	data := oob[unix.CmsgSpace(0) : unix.CmsgSpace(0)+unix.SizeofSockaddrInet6]
	binary.NativeEndian.PutUint16(data[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(data[2:4], ap.Port())
	ip := ap.Addr().As16()
	copy(data[8:24], ip[:])
	return oob
}
