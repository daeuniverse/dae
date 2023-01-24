/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package common

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func CloneStrings(slice []string) []string {
	c := make([]string, len(slice))
	copy(c, slice)
	return c
}

func ARangeU32(n uint32) []uint32 {
	ret := make([]uint32, n)
	for i := uint32(0); i < n; i++ {
		ret[i] = i
	}
	return ret
}

func Ipv6ByteSliceToUint32Array(_ip []byte) (ip [4]uint32) {
	for j := 0; j < 16; j += 4 {
		ip[j/4] = binary.LittleEndian.Uint32(_ip[j : j+4])
	}
	return ip
}

func Deduplicate(list []string) []string {
	res := make([]string, 0, len(list))
	m := make(map[string]struct{})
	for _, v := range list {
		if _, ok := m[v]; ok {
			continue
		}
		m[v] = struct{}{}
		res = append(res, v)
	}
	return res
}

func Base64UrlDecode(s string) (string, error) {
	s = strings.TrimSpace(s)
	saver := s
	if len(s)%4 > 0 {
		s += strings.Repeat("=", 4-len(s)%4)
	}
	raw, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return saver, err
	}
	return string(raw), nil
}

func Base64StdDecode(s string) (string, error) {
	s = strings.TrimSpace(s)
	saver := s
	if len(s)%4 > 0 {
		s += strings.Repeat("=", 4-len(s)%4)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return saver, err
	}
	return string(raw), nil
}

func SetValue(values *url.Values, key string, value string) {
	if value == "" {
		return
	}
	values.Set(key, value)
}

func ParseMac(mac string) (addr [6]byte, err error) {
	fields := strings.SplitN(mac, ":", 6)
	if len(fields) != 6 {
		return addr, fmt.Errorf("invalid mac: %v", mac)
	}
	for i, field := range fields {
		v, err := hex.DecodeString(field)
		if err != nil {
			return addr, fmt.Errorf("parse mac %v: %w", mac, err)
		}
		if len(v) != 1 {
			return addr, fmt.Errorf("invalid mac: %v", mac)
		}
		addr[i] = v[0]
	}
	return addr, nil
}

func ParsePortRange(pr string) (portRange [2]int, err error) {
	fields := strings.SplitN(pr, "-", 2)
	for i, field := range fields {
		if field == "" {
			return portRange, fmt.Errorf("bad port range: %v", pr)
		}
		port, err := strconv.Atoi(field)
		if err != nil {
			return portRange, err
		}
		if port < 0 || port > 0xffff {
			return portRange, fmt.Errorf("port %v exceeds uint16 range", port)
		}
		portRange[i] = port
	}
	if len(fields) == 1 {
		portRange[1] = portRange[0]
	}
	return portRange, nil
}
