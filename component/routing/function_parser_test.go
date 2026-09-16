/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// The routing grammar accepts `key: value` inside every function call, and the
// operands reach a parser grouped by key. The functions whose operands are bare
// values therefore have to reject a non-empty key themselves: before that
// check, `port(bogus_param: 443)` was folded into the operand list and built
// exactly the same match set as `port(443)`, so a mistyped parameter name
// became a different, effective rule with no error on either the `dae run` or
// the `dae validate` path.

func valueOnlyTestLogger() *logrus.Logger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

// valueOnlyParser is one value-only function: how to build its parser and one
// legal bare operand list.
type valueOnlyParser struct {
	name   string
	values []string
	parse  func(t *testing.T, key string) error
}

func valueOnlyParsers() []valueOnlyParser {
	return []valueOnlyParser{
		{
			name:   consts.Function_Ip,
			values: []string{"192.0.2.0/24", "2001:db8::/32"},
			parse: func(t *testing.T, key string) error {
				parser := IpParserFactory(func(_ *config_parser.Function, cidrs []netip.Prefix, _ *Outbound) error {
					require.Len(t, cidrs, 2)
					require.Equal(t, "192.0.2.0/24", cidrs[0].String())
					return nil
				})
				return parser(valueOnlyTestLogger(), &config_parser.Function{Name: consts.Function_Ip}, key, []string{"192.0.2.0/24", "2001:db8::/32"}, &Outbound{})
			},
		},
		{
			name:   consts.Function_SourceIp,
			values: []string{"192.0.2.1"},
			parse: func(t *testing.T, key string) error {
				parser := IpParserFactory(func(_ *config_parser.Function, _ []netip.Prefix, _ *Outbound) error { return nil })
				return parser(valueOnlyTestLogger(), &config_parser.Function{Name: consts.Function_SourceIp}, key, []string{"192.0.2.1"}, &Outbound{})
			},
		},
		{
			name:   consts.Function_Mac,
			values: []string{"aa:bb:cc:dd:ee:ff"},
			parse: func(t *testing.T, key string) error {
				parser := MacParserFactory(func(_ *config_parser.Function, macs [][6]byte, _ *Outbound) error {
					require.Len(t, macs, 1)
					return nil
				})
				return parser(valueOnlyTestLogger(), &config_parser.Function{Name: consts.Function_Mac}, key, []string{"aa:bb:cc:dd:ee:ff"}, &Outbound{})
			},
		},
		{
			name:   consts.Function_Port,
			values: []string{"443", "10080-30000"},
			parse: func(t *testing.T, key string) error {
				parser := PortRangeParserFactory(func(_ *config_parser.Function, ranges [][2]uint16, _ *Outbound) error {
					require.Len(t, ranges, 2)
					require.Equal(t, [2]uint16{443, 443}, ranges[0])
					return nil
				})
				return parser(valueOnlyTestLogger(), &config_parser.Function{Name: consts.Function_Port}, key, []string{"443", "10080-30000"}, &Outbound{})
			},
		},
		{
			name:   consts.Function_L4Proto,
			values: []string{"tcp"},
			parse: func(t *testing.T, key string) error {
				parser := L4ProtoParserFactory(func(_ *config_parser.Function, l4proto consts.L4ProtoType, _ *Outbound) error {
					require.Equal(t, consts.L4ProtoType_TCP, l4proto)
					return nil
				})
				return parser(valueOnlyTestLogger(), &config_parser.Function{Name: consts.Function_L4Proto}, key, []string{"tcp"}, &Outbound{})
			},
		},
		{
			name:   consts.Function_IpVersion,
			values: []string{"4"},
			parse: func(t *testing.T, key string) error {
				parser := IpVersionParserFactory(func(_ *config_parser.Function, version consts.IpVersionType, _ *Outbound) error {
					require.Equal(t, consts.IpVersion_4, version)
					return nil
				})
				return parser(valueOnlyTestLogger(), &config_parser.Function{Name: consts.Function_IpVersion}, key, []string{"4"}, &Outbound{})
			},
		},
		{
			name:   consts.Function_ProcessName,
			values: []string{"curl"},
			parse: func(t *testing.T, key string) error {
				parser := ProcessNameParserFactory(func(_ *config_parser.Function, names [][consts.TaskCommLen]byte, _ *Outbound) error {
					require.Len(t, names, 1)
					require.Equal(t, "curl", strings.TrimRight(string(names[0][:]), "\x00"))
					return nil
				})
				return parser(valueOnlyTestLogger(), &config_parser.Function{Name: consts.Function_ProcessName}, key, []string{"curl"}, &Outbound{})
			},
		},
		{
			name:   consts.Function_Dscp,
			values: []string{"0x4"},
			parse: func(t *testing.T, key string) error {
				parser := UintParserFactory(func(_ *config_parser.Function, values []uint8, _ *Outbound) error {
					require.Equal(t, []uint8{4}, values)
					return nil
				})
				return parser(valueOnlyTestLogger(), &config_parser.Function{Name: consts.Function_Dscp}, key, []string{"0x4"}, &Outbound{})
			},
		},
		{
			name:   consts.Function_Upstream,
			values: []string{"googledns"},
			parse: func(t *testing.T, key string) error {
				parser := EmptyKeyPlainParserFactory(func(_ *config_parser.Function, values []string, _ *Outbound) error {
					require.Equal(t, []string{"googledns"}, values)
					return nil
				})
				return parser(valueOnlyTestLogger(), &config_parser.Function{Name: consts.Function_Upstream}, key, []string{"googledns"}, &Outbound{})
			},
		},
	}
}

// TestValueOnlyFunctionsAcceptBareValues pins that the documented short form
// still works: the empty key is what the grammar produces for `pname(curl)`,
// `port(443)` and friends, and it stays accepted.
func TestValueOnlyFunctionsAcceptBareValues(t *testing.T) {
	for _, tc := range valueOnlyParsers() {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, tc.parse(t, ""))
		})
	}
}

// TestValueOnlyFunctionsRejectNamedParameters is the regression: every one of
// these functions used to ignore the key, so a typo silently built a different
// rule. The error has to name the function, the rejected key and the accepted
// form, because that is all a user has to go on.
func TestValueOnlyFunctionsRejectNamedParameters(t *testing.T) {
	const bogusKey = "bogus_param"
	for _, tc := range valueOnlyParsers() {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.parse(t, bogusKey)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.name+": unsupported parameter key")
			require.Contains(t, err.Error(), `"`+bogusKey+`"`)
			require.Contains(t, err.Error(), tc.name+"(<value>)")
		})
	}
}

// TestPlainParserFactoryKeepsForwardingTheKey guards the other half of the
// contract: the key-aware functions (domain, qname) must keep receiving their
// key so their own whitelists stay in charge.
func TestPlainParserFactoryKeepsForwardingTheKey(t *testing.T) {
	var got string
	parser := PlainParserFactory(func(_ *config_parser.Function, key string, _ []string, _ *Outbound) error {
		got = key
		return nil
	})
	require.NoError(t, parser(valueOnlyTestLogger(), &config_parser.Function{Name: consts.Function_Domain}, string(consts.RoutingDomainKey_Suffix), []string{"a.com"}, &Outbound{}))
	require.Equal(t, string(consts.RoutingDomainKey_Suffix), got)
}
