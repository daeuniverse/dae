/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
)

const (
	ContentType_HandShake                byte   = 22
	HandShakeType_Hello                  byte   = 1
	TlsExtension_ServerName              uint16 = 0
	TlsExtension_ServerNameType_HostName byte   = 0
)

var (
	Version_Tls1_0 = []byte{0x03, 0x01}
	Version_Tls1_2 = []byte{0x03, 0x03}
)

// SniffTls only supports tls1.2, tls1.3
func (s *Sniffer) SniffTls() (d string, err error) {
	// The Transport Layer Security (TLS) Protocol Version 1.3
	// https://www.rfc-editor.org/rfc/rfc8446#page-27
	boundary := 5
	if s.buf.Len() < boundary {
		return "", ErrNotApplicable
	}

	if s.buf.Bytes()[0] != ContentType_HandShake || (!bytes.Equal(s.buf.Bytes()[1:3], Version_Tls1_0) && !bytes.Equal(s.buf.Bytes()[1:3], Version_Tls1_2)) {
		return "", ErrNotApplicable
	}

	length := int(binary.BigEndian.Uint16(s.buf.Bytes()[3:5]))
	search := s.buf.Bytes()[5:]
	if len(search) < length {
		return "", ErrNotApplicable
	}
	return extractSniFromTls(quicutils.BuiltinBytesLocator(search[:length]))
}

func extractSniFromTls(search quicutils.Locator) (sni string, err error) {
	boundary := 39
	if search.Len() < boundary {
		return "", ErrNotApplicable
	}
	// Transport Layer Security (TLS) Extensions: Extension Definitions
	// https://www.rfc-editor.org/rfc/rfc6066#page-5
	b, err := search.Range(0, 6)
	if err != nil {
		return "", err
	}
	if b[0] != HandShakeType_Hello {
		return "", ErrNotApplicable
	}

	// Three bytes length.
	length2 := (int(b[1]) << 16) + (int(b[2]) << 8) + int(b[3])
	if search.Len() > length2+4 {
		return "", ErrNotApplicable
	}

	if !bytes.Equal(b[4:], Version_Tls1_2) {
		return "", ErrNotApplicable
	}

	// Skip 32 bytes random.

	sessionIdLength, err := search.At(boundary - 1)
	if err != nil {
		return "", err
	}
	boundary += int(sessionIdLength) + 2 // +2 because the next field has 2B length
	if search.Len() < boundary || search.Len() < boundary {
		return "", ErrNotApplicable
	}

	b, err = search.Range(boundary-2, boundary)
	if err != nil {
		return "", err
	}
	cipherSuiteLength := int(binary.BigEndian.Uint16(b))
	boundary += int(cipherSuiteLength) + 1 // +1 because the next field has 1B length
	if search.Len() < boundary || search.Len() < boundary {
		return "", ErrNotApplicable
	}

	compressMethodsLength, err := search.At(boundary - 1)
	if err != nil {
		return "", err
	}
	boundary += int(compressMethodsLength) + 2 // +2 because the next field has 2B length
	if search.Len() < boundary || search.Len() < boundary {
		return "", ErrNotApplicable
	}

	b, err = search.Range(boundary-2, boundary)
	if err != nil {
		return "", err
	}
	extensionsLength := int(binary.BigEndian.Uint16(b))
	boundary += extensionsLength + 0 // +0 because our search ends
	if search.Len() < boundary || search.Len() < boundary {
		return "", ErrNotApplicable
	}
	// Search SNI
	extensions, err := search.Slice(boundary-extensionsLength, boundary)
	if err != nil {
		return "", err
	}
	return findSniExtension(extensions)
}

func findSniExtension(search quicutils.Locator) (d string, err error) {
	i := 0
	var b []byte
	for {
		if i+4 >= search.Len() {
			return "", ErrNotFound
		}
		b, err = search.Range(i, i+4)
		if err != nil {
			return "", err
		}
		typ := binary.BigEndian.Uint16(b)
		extLength := int(binary.BigEndian.Uint16(b[2:]))

		iNextField := i + 4 + extLength
		if iNextField > search.Len() {
			return "", ErrNotApplicable
		}
		if typ == TlsExtension_ServerName {
			b, err = search.Range(i+4, i+6)
			if err != nil {
				return "", err
			}
			sniLen := int(binary.BigEndian.Uint16(b))
			if extLength < sniLen+2 {
				return "", ErrNotApplicable
			}
			// Search HostName type SNI.
			for j, indicatorLen := i+6, 0; j+3 <= iNextField; j += indicatorLen {
				b, err = search.Range(j, j+3)
				if err != nil {
					return "", err
				}
				indicatorLen = int(binary.BigEndian.Uint16(b[1:]))
				if b[0] != TlsExtension_ServerNameType_HostName {
					continue
				}
				if j+3+indicatorLen > iNextField {
					return "", ErrNotApplicable
				}
				b, err = search.Range(j+3, j+3+indicatorLen)
				if err != nil {
					return "", err
				}
				// An SNI value may not include a trailing dot.
				// https://tools.ietf.org/html/rfc6066#section-3
				// But we accept it here.
				return strings.TrimSuffix(string(b), "."), nil
			}
		}
		i = iNextField
	}
}
