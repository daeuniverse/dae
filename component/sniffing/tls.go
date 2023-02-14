/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"encoding/binary"
	"github.com/v2rayA/dae/component/sniffing/internal/quicutils"
)

const (
	ContentType_HandShake                byte   = 22
	HandShakeType_Hello                  byte   = 1
	TlsExtension_ServerName              uint16 = 0
	TlsExtension_ServerNameType_HostName byte   = 0
)

var (
	Version_Tls1_0  = []byte{0x03, 0x01}
	Version_Tls1_2  = []byte{0x03, 0x03}
	HandShakePrefix = []byte{ContentType_HandShake, Version_Tls1_0[0], Version_Tls1_0[1]}
)

// SniffTls only supports tls1.2, tls1.3
func (s *Sniffer) SniffTls() (d string, err error) {
	// The Transport Layer Security (TLS) Protocol Version 1.3
	// https://www.rfc-editor.org/rfc/rfc8446#page-27
	boundary := 5
	if len(s.buf) < boundary {
		return "", NotApplicableError
	}

	if !bytes.Equal(s.buf[:3], HandShakePrefix) {
		return "", NotApplicableError
	}

	length := int(binary.BigEndian.Uint16(s.buf[3:5]))
	search := s.buf[5:]
	if len(search) < length {
		return "", NotApplicableError
	}
	return extractSniFromTls(quicutils.BuiltinBytesLocator(search[:length]))
}

func extractSniFromTls(search quicutils.Locator) (sni string, err error) {
	boundary := 39
	if search.Len() < boundary {
		return "", NotApplicableError
	}
	// Transport Layer Security (TLS) Extensions: Extension Definitions
	// https://www.rfc-editor.org/rfc/rfc6066#page-5
	b := search.Range(0, 6)
	if b[0] != HandShakeType_Hello {
		return "", NotApplicableError
	}

	// Three bytes length.
	length2 := (int(b[1]) << 16) + (int(b[2]) << 8) + int(b[3])
	if search.Len() > length2+4 {
		return "", NotApplicableError
	}

	if !bytes.Equal(b[4:], Version_Tls1_2) {
		return "", NotApplicableError
	}

	// Skip 32 bytes random.

	sessionIdLength := search.At(boundary - 1)
	boundary += int(sessionIdLength) + 2 // +2 because the next field has 2B length
	if search.Len() < boundary || search.Len() < boundary {
		return "", NotApplicableError
	}

	b = search.Range(boundary-2, boundary)
	cipherSuiteLength := int(binary.BigEndian.Uint16(b))
	boundary += int(cipherSuiteLength) + 1 // +1 because the next field has 1B length
	if search.Len() < boundary || search.Len() < boundary {
		return "", NotApplicableError
	}

	compressMethodsLength := search.At(boundary - 1)
	boundary += int(compressMethodsLength) + 2 // +2 because the next field has 2B length
	if search.Len() < boundary || search.Len() < boundary {
		return "", NotApplicableError
	}

	b = search.Range(boundary-2, boundary)
	extensionsLength := int(binary.BigEndian.Uint16(b))
	boundary += extensionsLength + 0 // +0 because our search ends
	if search.Len() < boundary || search.Len() < boundary {
		return "", NotApplicableError
	}
	// Search SNI
	return findSniExtension(search.Slice(boundary-extensionsLength, boundary))
}

func findSniExtension(search quicutils.Locator) (string, error) {
	i := 0
	var b []byte
	for {
		if i+4 >= search.Len() {
			return "", NotApplicableError
		}
		b = search.Range(i, i+4)
		typ := binary.BigEndian.Uint16(b)
		extLength := int(binary.BigEndian.Uint16(b[2:]))

		iNextField := i + 4 + extLength
		if iNextField > search.Len() {
			return "", NotApplicableError
		}
		if typ == TlsExtension_ServerName {
			b = search.Range(i+4, i+9)
			sniLen := int(binary.BigEndian.Uint16(b))
			if extLength != sniLen+2 {
				return "", NotApplicableError
			}
			// There may be multiple server names, we only pick the first.
			if b[2] != TlsExtension_ServerNameType_HostName {
				return "", NotApplicableError
			}
			snLen := int(binary.BigEndian.Uint16(b[3:]))
			if i+9+snLen > iNextField {
				return "", NotApplicableError
			}
			b = search.Range(i+9, i+9+snLen)
			sni := string(b)
			return sni, nil
		}
		i = iNextField
	}
}
