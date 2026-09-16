/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	stderrors "errors"

	dnsmessage "github.com/miekg/dns"
)

// packQuestionWireName encodes one domain name into dst as an uncompressed DNS
// wire name and returns the encoded bytes. It returns nil when the name cannot
// be encoded (not fully qualified, label longer than 63 bytes, name longer than
// 255 bytes, or dst too small), so callers can keep the existing wire unchanged
// rather than guess.
//
// The question name of a packed message is never compressed (it is the first
// name in the message), which makes the encoded length directly comparable with
// the question name already present in that message.
func packQuestionWireName(name string, dst []byte) []byte {
	if name == "" || len(dst) == 0 {
		return nil
	}
	end, err := dnsmessage.PackDomainName(name, dst, 0, nil, false)
	if err != nil || end <= 0 {
		return nil
	}
	return dst[:end]
}

// dnsRRTypeOpt is the EDNS0 OPT pseudo-RR type. Its 32-bit field after the
// name carries flags and the advertised UDP size, not a TTL, so it must be
// excluded from TTL rewrites.
const dnsRRTypeOpt = 41

// skipDnsWireName advances past one domain name in a wire-format DNS message,
// following compression pointers (RFC 1035 §4.1.4). It returns the offset
// just past the name, or -1 when the name is malformed. Label types other
// than plain labels and pointers are rejected.
func skipDnsWireName(msg []byte, off int) int {
	if off < 0 || off >= len(msg) {
		return -1
	}
	// Track visited pointer targets so pointer loops terminate.
	visited := make(map[int]struct{})
	for {
		if off >= len(msg) {
			return -1
		}
		b := msg[off]
		switch {
		case b == 0:
			// Root label: the name ends here; the caller continues at off+1.
			return off + 1
		case b&0xc0 == 0xc0:
			// Compression pointer: the name may continue at the target, but
			// the wire position only advances by two bytes.
			if off+1 >= len(msg) {
				return -1
			}
			target := int(b&0x3f)<<8 | int(msg[off+1])
			if _, seen := visited[target]; seen {
				return -1
			}
			visited[target] = struct{}{}
			// Follow the pointer target to keep validating the remainder of
			// the name; the pointer itself is the end of the name.
			if err := validateDnsWireNameAt(msg, target, visited); err != nil {
				return -1
			}
			return off + 2
		case b&0xc0 == 0x00:
			// Plain label.
			l := int(b)
			if off+1+l >= len(msg) {
				return -1
			}
			off += 1 + l
		default:
			// Reserved label types (0x40/0x80); do not guess.
			return -1
		}
	}
}

func validateDnsWireNameAt(msg []byte, off int, visited map[int]struct{}) error {
	for {
		if off < 0 || off >= len(msg) {
			return errMalformedDnsWire
		}
		b := msg[off]
		switch {
		case b == 0:
			return nil
		case b&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return errMalformedDnsWire
			}
			target := int(b&0x3f)<<8 | int(msg[off+1])
			if _, seen := visited[target]; seen {
				return errMalformedDnsWire
			}
			visited[target] = struct{}{}
			off = target
		case b&0xc0 == 0x00:
			off += 1 + int(b)
			if off >= len(msg) {
				return errMalformedDnsWire
			}
		default:
			return errMalformedDnsWire
		}
	}
}

var errMalformedDnsWire = stderrors.New("malformed DNS wire message")

// clampWireRecordTtls returns a copy of msg in which every real resource
// record's TTL is clamped to at most maxTtl. Records whose TTL is already
// zero (dae-managed A/AAAA answers) and the EDNS OPT pseudo-record are left
// untouched. It returns nil when the message cannot be walked safely.
//
// Used to bound the TTL advertised for served-stale (RFC 8767) answers:
// replaying the original multi-hour TTL on an expired answer would make
// downstream clients cache the stale data long after the daemon stopped
// serving it.
func clampWireRecordTtls(msg []byte, maxTtl uint32) []byte {
	if maxTtl == 0 || len(msg) < 12 {
		return nil
	}
	out := make([]byte, len(msg))
	copy(out, msg)

	// Walk sections: header(12) then Question(s), then Answer/Authority/
	// Additional (RFC 1035 §4.1). Question count = qdcount; resource records
	// follow in order ancount, nscount, arcount.
	qd := int(binary.BigEndian.Uint16(out[4:6]))
	an := int(binary.BigEndian.Uint16(out[6:8]))
	ns := int(binary.BigEndian.Uint16(out[8:10]))
	ar := int(binary.BigEndian.Uint16(out[10:12]))

	off := 12
	for range qd {
		nameEnd := skipDnsWireName(out, off)
		if nameEnd < 0 {
			return nil
		}
		off = nameEnd + 4 // QTYPE(2) + QCLASS(2)
		if off > len(out) {
			return nil
		}
	}

	walkRRs := func(count int) bool {
		for range count {
			nameEnd := skipDnsWireName(out, off)
			if nameEnd < 0 {
				return false
			}
			// TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) RDLEN bytes.
			rrHeaderEnd := nameEnd + 10
			if rrHeaderEnd > len(out) {
				return false
			}
			rrType := binary.BigEndian.Uint16(out[nameEnd : nameEnd+2])
			rdLen := int(binary.BigEndian.Uint16(out[nameEnd+8 : nameEnd+10]))
			if rrHeaderEnd+rdLen > len(out) {
				return false
			}
			if rrType != dnsRRTypeOpt {
				ttl := binary.BigEndian.Uint32(out[nameEnd+4 : nameEnd+8])
				if ttl > maxTtl && ttl != 0 {
					binary.BigEndian.PutUint32(out[nameEnd+4:nameEnd+8], maxTtl)
				}
			}
			off = rrHeaderEnd + rdLen
		}
		return true
	}
	if !walkRRs(an) || !walkRRs(ns) || !walkRRs(ar) {
		return nil
	}
	if off != len(out) {
		// Trailing garbage is suspicious; refuse rather than serve a
		// half-rewritten message.
		return nil
	}
	return out
}
