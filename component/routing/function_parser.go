/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"encoding/binary"
	stderrors "errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/constraints"
)

type FunctionParser func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error)

// Preset function parser factories.

// PlainParserFactory is for style unity.
func PlainParserFactory(callback func(f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error)) FunctionParser {
	return func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		return callback(f, key, paramValueGroup, overrideOutbound)
	}
}

// EmptyKeyPlainParserFactory only accepts function with empty key.
func EmptyKeyPlainParserFactory(callback func(f *config_parser.Function, values []string, overrideOutbound *Outbound) (err error)) FunctionParser {
	return emptyKeyOnly(func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		return callback(f, paramValueGroup, overrideOutbound)
	})
}

// emptyKeyOnly rejects named parameters for the functions whose operands are
// bare values.
//
// The config grammar accepts `key: value` inside every function call and groups
// the operands by key before a parser sees them, but the value-only parsers used
// to ignore the key entirely. A mistyped parameter name therefore did not fail:
// its value was folded into the operand list, so `port(bogus_param: 443)` built
// the same match set as `port(443)`, `pname(bogus_param: 1)` matched a process
// literally named "1", and `dae run` and `dae validate` both accepted it
// silently. The bare form is the documented spelling (`pname(curl)`,
// `port(443)`, `dip(geoip:cn)`, whose `geoip` key is expanded into bare CIDRs
// before lowering), so an empty key stays accepted while a non-empty one is
// reported with the function name, the rejected key and the accepted form - a
// typo has to be a loud failure rather than a different, effective rule.
//
// Key-aware functions (domain, qname) use PlainParserFactory and validate their
// keys themselves (addDomain/addQName).
func emptyKeyOnly(parse FunctionParser) FunctionParser {
	return func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		if key != "" {
			name := "this function"
			if f != nil {
				name = f.Name
			}
			return fmt.Errorf("%v: unsupported parameter key %v; %v takes bare values only and accepts no named parameter, so write %v(<value>)", name, strconv.Quote(key), name, name)
		}
		return parse(log, f, key, paramValueGroup, overrideOutbound)
	}
}

func IpParserFactory(callback func(f *config_parser.Function, cidrs []netip.Prefix, overrideOutbound *Outbound) (err error)) FunctionParser {
	return emptyKeyOnly(func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		cidrs, err := parsePrefixes(paramValueGroup)
		if err != nil {
			return err
		}
		return callback(f, cidrs, overrideOutbound)
	})
}

func MacParserFactory(callback func(f *config_parser.Function, macAddrs [][6]byte, overrideOutbound *Outbound) (err error)) FunctionParser {
	return emptyKeyOnly(func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		var macAddrs [][6]byte
		for _, v := range paramValueGroup {
			mac, err := common.ParseMac(v)
			if err != nil {
				return err
			}
			macAddrs = append(macAddrs, mac)
		}
		return callback(f, macAddrs, overrideOutbound)
	})
}

func PortRangeParserFactory(callback func(f *config_parser.Function, portRanges [][2]uint16, overrideOutbound *Outbound) (err error)) FunctionParser {
	return emptyKeyOnly(func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		var portRanges [][2]uint16
		for _, v := range paramValueGroup {
			portRange, err := common.ParsePortRange(v)
			if err != nil {
				return err
			}
			portRanges = append(portRanges, portRange)
		}
		return callback(f, portRanges, overrideOutbound)
	})
}

func L4ProtoParserFactory(callback func(f *config_parser.Function, l4protoType consts.L4ProtoType, overrideOutbound *Outbound) (err error)) FunctionParser {
	return emptyKeyOnly(func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		var l4protoType consts.L4ProtoType
		for _, v := range paramValueGroup {
			switch v {
			case "tcp":
				l4protoType |= consts.L4ProtoType_TCP
			case "udp":
				l4protoType |= consts.L4ProtoType_UDP
			default:
				return fmt.Errorf("l4proto: unknown value %v; supported values are tcp and udp", strconv.Quote(v))
			}
		}
		if l4protoType == 0 {
			return stderrors.New("l4proto: at least one of tcp and udp is required")
		}
		return callback(f, l4protoType, overrideOutbound)
	})
}

func IpVersionParserFactory(callback func(f *config_parser.Function, ipVersion consts.IpVersionType, overrideOutbound *Outbound) (err error)) FunctionParser {
	return emptyKeyOnly(func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		var ipVersion consts.IpVersionType
		for _, v := range paramValueGroup {
			switch v {
			case "4":
				ipVersion |= consts.IpVersion_4
			case "6":
				ipVersion |= consts.IpVersion_6
			default:
				return fmt.Errorf("ipversion: unknown value %v; supported values are 4 and 6", strconv.Quote(v))
			}
		}
		if ipVersion == 0 {
			return stderrors.New("ipversion: at least one of 4 and 6 is required")
		}
		return callback(f, ipVersion, overrideOutbound)
	})
}

func ProcessNameParserFactory(callback func(f *config_parser.Function, procNames [][consts.TaskCommLen]byte, overrideOutbound *Outbound) (err error)) FunctionParser {
	return emptyKeyOnly(func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		var procNames [][consts.TaskCommLen]byte
		for _, v := range paramValueGroup {
			if len([]byte(v)) > consts.TaskCommLen {
				log.Infof(`pname routing: trim "%v" to "%v" because it is too long.`, v, string([]byte(v)[:consts.TaskCommLen]))
			}
			procNames = append(procNames, toProcessName(v))
		}
		return callback(f, procNames, overrideOutbound)
	})
}

func parsePrefixes(values []string) (cidrs []netip.Prefix, err error) {
	for _, value := range values {
		toParse := value
		if strings.LastIndexByte(value, '/') == -1 {
			if strings.Contains(value, ":") {
				toParse += "/128"
			} else {
				toParse += "/32"
			}
		}
		prefix, err := netip.ParsePrefix(toParse)
		if err != nil {
			return nil, fmt.Errorf("cannot parse %v: %w", value, err)
		}
		cidrs = append(cidrs, prefix)
	}
	return cidrs, nil
}

func toProcessName(processName string) (procName [consts.TaskCommLen]byte) {
	n := []byte(processName)
	copy(procName[:], n)
	return procName
}

func UintParserFactory[T constraints.Unsigned](callback func(f *config_parser.Function, values []T, overrideOutbound *Outbound) (err error)) FunctionParser {
	size := binary.Size(new(T))
	return emptyKeyOnly(func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		var values []T
		for _, v := range paramValueGroup {
			val, err := strconv.ParseUint(v, 0, 8*size)
			if err != nil {
				return fmt.Errorf("cannot parse %v: %w", v, err)
			}
			values = append(values, T(val))
		}
		return callback(f, values, overrideOutbound)
	})
}
