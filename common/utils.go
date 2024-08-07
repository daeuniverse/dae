/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/daeuniverse/outbound/netproxy"

	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	dnsmessage "github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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
		ip[j/4] = internal.NativeEndian.Uint32(_ip[j : j+4])
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
		internal.NativeEndian.PutUint32(ip[j*4:], _ip[j])
	}
	return ip
}

func Deduplicate(list []string) []string {
	if list == nil {
		return nil
	}
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
		i, err := strconv.ParseInt(val, 0, strconv.IntSize)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int8:
		i, err := strconv.ParseInt(val, 0, 8)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int16:
		i, err := strconv.ParseInt(val, 0, 16)
		if err != nil {
			return false
		}
		v.SetInt(i)
	case reflect.Int32:
		i, err := strconv.ParseInt(val, 0, 32)
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
			i, err := strconv.ParseInt(val, 0, 64)
			if err != nil {
				return false
			}
			v.SetInt(i)
		}
	case reflect.Uint:
		i, err := strconv.ParseUint(val, 0, strconv.IntSize)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint8:
		i, err := strconv.ParseUint(val, 0, 8)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint16:
		i, err := strconv.ParseUint(val, 0, 16)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint32:
		i, err := strconv.ParseUint(val, 0, 32)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Uint64:
		i, err := strconv.ParseUint(val, 0, 64)
		if err != nil {
			return false
		}
		v.SetUint(i)
	case reflect.Bool:
		switch strings.ToLower(val) {
		case "true", "t", "1", "y", "yes", "on":
			v.SetBool(true)
		case "false", "f", "0", "n", "no", "off":
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
	case reflect.Slice:
		switch v.Interface().(type) {
		case []string:
			v.Set(reflect.ValueOf(strings.Split(val, ",")))
		case []time.Duration:
			var durations []time.Duration
			duration, err := time.ParseDuration(val)
			if err != nil {
				return false
			}
			durations = append(durations, duration)
			v.Set(reflect.ValueOf(durations))
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

func ConvergeAddr(addr netip.Addr) netip.Addr {
	if addr.Is4In6() {
		addr = netip.AddrFrom4(addr.As4())
	}
	return addr
}

func ConvergeAddrPort(addrPort netip.AddrPort) netip.AddrPort {
	if addrPort.Addr().Is4In6() {
		return netip.AddrPortFrom(netip.AddrFrom4(addrPort.Addr().As4()), addrPort.Port())
	}
	return addrPort
}

func NewGcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func AddrToDnsType(addr netip.Addr) uint16 {
	if addr.Is4() {
		return dnsmessage.TypeA
	} else {
		return dnsmessage.TypeAAAA
	}
}

// Htons converts the unsigned short integer hostshort from host byte order to network byte order.
func Htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// Ntohs converts the unsigned short integer hostshort from host byte order to network byte order.
func Ntohs(i uint16) uint16 {
	bytes := *(*[2]byte)(unsafe.Pointer(&i))
	return binary.BigEndian.Uint16(bytes[:])
}

func GetDefaultIfnames() (defaultIfs []string, err error) {
	linkList, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
nextLink:
	for _, link := range linkList {
		if link.Attrs().Flags&unix.RTF_UP != unix.RTF_UP {
			// Interface is down.
			continue
		}
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			rs, err := netlink.RouteList(link, family)
			if err != nil {
				return nil, err
			}
			for _, route := range rs {
				if route.Dst != nil {
					continue
				}
				// Have no dst, it is a default route.
				defaultIfs = append(defaultIfs, link.Attrs().Name)
				continue nextLink
			}
		}
	}
	return Deduplicate(defaultIfs), nil
}

func MagicNetwork(network string, mark uint32, mptcp bool) string {
	if mark == 0 && !mptcp {
		return network
	} else {
		return netproxy.MagicNetwork{
			Network: network,
			Mark:    mark,
			Mptcp:   mptcp,
		}.Encode()
	}
}

func IsValidHttpMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "COPY", "HEAD", "OPTIONS", "LINK", "UNLINK", "PURGE", "LOCK", "UNLOCK", "PROPFIND", "CONNECT", "TRACE":
		return true
	default:
		return false
	}
}

func StringSet(list []string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, s := range list {
		m[s] = struct{}{}
	}
	return m
}

func GenerateCertChainHash(rawCerts [][]byte) (chainHash []byte) {
	for _, cert := range rawCerts {
		certHash := sha256.Sum256(cert)
		if chainHash == nil {
			chainHash = certHash[:]
		} else {
			newHash := sha256.Sum256(append(chainHash, certHash[:]...))
			chainHash = newHash[:]
		}
	}
	return chainHash
}
