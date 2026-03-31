/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/eknkc/basex"
)

const Alphabet = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789"
const Alphabet64Grpc = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789_."

var Base62Encoder, _ = basex.NewEncoding(Alphabet)
var Base64GrpcEncoder, _ = basex.NewEncoding(Alphabet64Grpc)
var IntSize = 32 << (^uint(0) >> 63)

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

func BytesIncBigEndian(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

func BytesIncLittleEndian(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

func Abs64(a int64) int64 {
	if a < 0 {
		return -a
	}
	return a
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// StringToUUID5 is from https://github.com/XTLS/Xray-core/issues/158
func StringToUUID5(str string) string {
	var Nil [16]byte
	h := sha1.New()
	h.Write(Nil[:])
	h.Write([]byte(str))
	u := h.Sum(nil)[:16]
	u[6] = (u[6] & 0x0f) | (5 << 4)
	u[8] = u[8]&(0xff>>2) | (0x02 << 6)
	buf := make([]byte, 36)
	hex.Encode(buf[0:8], u[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], u[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], u[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], u[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:], u[10:])
	return string(buf)
}

func StringsHas(strs []string, str string) bool {
	for _, s := range strs {
		if s == str {
			return true
		}
	}
	return false
}

func HeadOverlap(p, b []byte) bool {
	return len(p) > 0 && len(b) > 0 && &p[0] == &b[0]
}

func ResolveUDPAddr(resolver *net.Resolver, hostport string) (*net.UDPAddr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host, _port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(_port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", _port)
	}
	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	// Prefer ipv4.
	var ip netip.Addr
	for _, addr := range addrs {
		if !ip.IsValid() {
			ip = addr
			continue
		}
		if addr.Is4() {
			ip = addr
			break
		}
	}
	if !ip.IsValid() {
		return nil, errors.New("no suitable address found")
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port))), nil
}

// // MultiWrite uses io.Copy to try to avoid seperated packets.
// func MultiWrite(dst io.Writer, bs ...[]byte) (int64, error) {
// 	readers := make([]io.Reader, 0, len(bs))
// 	for _, b := range bs {
// 		readers = append(readers, bytes.NewReader(b))
// 	}
// 	return io.Copy(dst, io.MultiReader(readers...))
// }
