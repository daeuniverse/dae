/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package common

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var (
	ErrOverlayHierarchicalKey = fmt.Errorf("overlay hierarchical key")
)

type UrlOrEmpty struct {
	Url   *url.URL
	Empty bool
}

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

func Ipv6ByteSliceToUint8Array(_ip []byte) (ip [16]uint8) {
	copy(ip[:], _ip)
	return ip
}

func Ipv6Uint32ArrayToByteSlice(_ip [4]uint32) (ip []byte) {
	ip = make([]byte, 16)
	for j := 0; j < 4; j++ {
		binary.LittleEndian.PutUint32(ip[j*4:], _ip[j])
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

func ParsePortRange(pr string) (portRange [2]uint16, err error) {
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
		portRange[i] = uint16(port)
	}
	if len(fields) == 1 {
		portRange[1] = portRange[0]
	}
	return portRange, nil
}

func SetValueHierarchicalMap(m map[string]interface{}, key string, val interface{}) error {
	keys := strings.Split(key, ".")
	lastKey := keys[len(keys)-1]
	keys = keys[:len(keys)-1]
	p := &m
	for _, key := range keys {
		if v, ok := (*p)[key]; ok {
			vv, ok := v.(map[string]interface{})
			if !ok {
				return ErrOverlayHierarchicalKey
			}
			p = &vv
		} else {
			(*p)[key] = make(map[string]interface{})
			vv := (*p)[key].(map[string]interface{})
			p = &vv
		}
	}
	(*p)[lastKey] = val
	return nil
}

func SetValueHierarchicalStruct(m interface{}, key string, val string) error {
	ifv, err := GetValueHierarchicalStruct(m, key)
	if err != nil {
		return err
	}
	if !FuzzyDecode(ifv.Addr().Interface(), val) {
		return fmt.Errorf("type does not match: type \"%v\" and value \"%v\"", ifv.Kind(), val)
	}
	return nil
}

func GetValueHierarchicalStruct(m interface{}, key string) (reflect.Value, error) {
	keys := strings.Split(key, ".")
	ifv := reflect.Indirect(reflect.ValueOf(m))
	ift := ifv.Type()
	lastK := ""
	for _, k := range keys {
		found := false
		if ift.Kind() == reflect.Struct {
			for i := 0; i < ifv.NumField(); i++ {
				name, ok := ift.Field(i).Tag.Lookup("mapstructure")
				if ok && name == k {
					found = true
					ifv = ifv.Field(i)
					ift = ifv.Type()
					lastK = k
					break
				}
			}
		}
		if !found {
			return reflect.Value{}, fmt.Errorf(`unexpected key "%v": "%v" (%v type) has no member "%v"`, key, lastK, ift.Kind().String(), k)
		}
	}
	return ifv, nil
}

func FuzzyDecode(to interface{}, val string) bool {
	v := reflect.Indirect(reflect.ValueOf(to))
	switch v.Kind() {
	case reflect.Int:
		i, err := strconv.ParseInt(val, 10, strconv.IntSize)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int8:
		i, err := strconv.ParseInt(val, 10, 8)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int16:
		i, err := strconv.ParseInt(val, 10, 16)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int32:
		i, err := strconv.ParseInt(val, 10, 32)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int64:
		switch v.Interface().(type) {
		case time.Duration:
			duration, err := time.ParseDuration(val)
			if err != nil {
				return false
			}
			v.Set(reflect.ValueOf(duration))
		default:
			i, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return false
			}
			v.SetInt(i)
		}
	case reflect.Uint:
		i, err := strconv.ParseUint(val, 10, strconv.IntSize)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint8:
		i, err := strconv.ParseUint(val, 10, 8)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint16:
		i, err := strconv.ParseUint(val, 10, 16)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint32:
		i, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint64:
		i, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Bool:
		switch strings.ToLower(val) {
		case "true", "1", "y", "yes":
			v.SetBool(true)
		case "false", "0", "n", "no":
			v.SetBool(false)
		default:
			return false
		}
	case reflect.String:
		v.SetString(val)
	case reflect.Struct:
		switch v.Interface().(type) {
		case UrlOrEmpty:
			if val == "" {
				v.Set(reflect.ValueOf(UrlOrEmpty{
					Url:   nil,
					Empty: true,
				}))
			} else {
				u, err := url.Parse(val)
				if err != nil {
					return false
				}
				v.Set(reflect.ValueOf(UrlOrEmpty{
					Url:   u,
					Empty: false,
				}))
			}
		default:
			return false
		}
	default:
		return false
	}
	return true
}

func EnsureFileInSubDir(filePath string, dir string) (err error) {
	fileDir := filepath.Dir(filePath)
	if len(dir) == 0 {
		return fmt.Errorf("bad dir: %v", dir)
	}
	rel, err := filepath.Rel(dir, fileDir)
	if err != nil {
		return err
	}
	if strings.HasPrefix(rel, "..") {
		return fmt.Errorf("file is out of scope: %v", rel)
	}
	return nil
}

func MapKeys(m interface{}) (keys []string, err error) {
	v := reflect.ValueOf(m)
	if v.Kind() != reflect.Map {
		return nil, fmt.Errorf("MapKeys requires map[string]*")
	}
	if v.Type().Key().Kind() != reflect.String {
		return nil, fmt.Errorf("MapKeys requires map[string]*")
	}
	_keys := v.MapKeys()
	keys = make([]string, 0, len(_keys))
	for _, k := range _keys {
		keys = append(keys, k.String())
	}
	return keys, nil
}

func GetTagFromLinkLikePlaintext(link string) (tag string, afterTag string) {
	iColon := strings.Index(link, ":")
	if iColon == -1 {
		return "", link
	}
	// If first colon is like "://" in "scheme://linkbody", no tag is present.
	if strings.HasPrefix(link[iColon:], "://") {
		return "", link
	}
	// Else tag is the part before colon.
	return link[:iColon], link[iColon+1:]
}

func BoolToString(b bool) string {
	if b {
		return "1"
	} else {
		return "0"
	}
}

func ConvergeIp(addr netip.Addr) netip.Addr {
	if addr.Is4In6() {
		addr = netip.AddrFrom4(addr.As4())
	}
	return addr
}

func NewGcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func AddrToDnsType(addr netip.Addr) dnsmessage.Type {
	if addr.Is4() {
		return dnsmessage.TypeA
	} else {
		return dnsmessage.TypeAAAA
	}
}
