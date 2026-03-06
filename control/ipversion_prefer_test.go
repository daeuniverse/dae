/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestParseIpVersionPreference(t *testing.T) {
	qtype, err := parseIpVersionPreference(int(IpVersionPrefer_No))
	require.NoError(t, err)
	require.Equal(t, uint16(0), qtype)

	qtype, err = parseIpVersionPreference(int(IpVersionPrefer_4))
	require.NoError(t, err)
	require.Equal(t, uint16(dnsmessage.TypeA), qtype)

	qtype, err = parseIpVersionPreference(int(IpVersionPrefer_6))
	require.NoError(t, err)
	require.Equal(t, uint16(dnsmessage.TypeAAAA), qtype)
}

func TestParseIpVersionPreference_Invalid(t *testing.T) {
	_, err := parseIpVersionPreference(12345)
	require.Error(t, err)
}
