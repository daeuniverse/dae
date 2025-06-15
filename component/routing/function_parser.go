/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"encoding/binary"
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
	return func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		if key != "" {
			return fmt.Errorf("this function cannot accept a key")
		}
		return callback(f, paramValueGroup, overrideOutbound)
	}
}

func IpParserFactory(callback func(f *config_parser.Function, cidrs []netip.Prefix, overrideOutbound *Outbound) (err error)) FunctionParser {
	return func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		cidrs, err := parsePrefixes(paramValueGroup)
		if err != nil {
			return err
		}
		return callback(f, cidrs, overrideOutbound)
	}
}

func MacParserFactory(callback func(f *config_parser.Function, macAddrs [][6]byte, overrideOutbound *Outbound) (err error)) FunctionParser {
	return func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		var macAddrs [][6]byte
		for _, v := range paramValueGroup {
			mac, err := common.ParseMac(v)
			if err != nil {
				return err
			}
			macAddrs = append(macAddrs, mac)
		}
		return callback(f, macAddrs, overrideOutbound)
	}
}

func PortRangeParserFactory(callback func(f *config_parser.Function, portRanges [][2]uint16, overrideOutbound *Outbound) (err error)) FunctionParser {
	return func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		var portRanges [][2]uint16
		for _, v := range paramValueGroup {
			portRange, err := common.ParsePortRange(v)
			if err != nil {
				return err
			}
			portRanges = append(portRanges, portRange)
		}
		return callback(f, portRanges, overrideOutbound)
	}
}

func L4ProtoParserFactory(callback func(f *config_parser.Function, l4protoType consts.L4ProtoType, overrideOutbound *Outbound) (err error)) FunctionParser {
	return func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		var l4protoType consts.L4ProtoType
		for _, v := range paramValueGroup {
			switch v {
			case "tcp":
				l4protoType |= consts.L4ProtoType_TCP
			case "udp":
				l4protoType |= consts.L4ProtoType_UDP
			}
		}
		return callback(f, l4protoType, overrideOutbound)
	}
}

func IpVersionParserFactory(callback func(f *config_parser.Function, ipVersion consts.IpVersionType, overrideOutbound *Outbound) (err error)) FunctionParser {
	return func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		var ipVersion consts.IpVersionType
		for _, v := range paramValueGroup {
			switch v {
			case "4":
				ipVersion |= consts.IpVersion_4
			case "6":
				ipVersion |= consts.IpVersion_6
			}
		}
		return callback(f, ipVersion, overrideOutbound)
	}
}

func ProcessNameParserFactory(callback func(f *config_parser.Function, procNames [][consts.TaskCommLen]byte, overrideOutbound *Outbound) (err error)) FunctionParser {
	return func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		var procNames [][consts.TaskCommLen]byte
		for _, v := range paramValueGroup {
			if len([]byte(v)) > consts.TaskCommLen {
				log.Infof(`pname routing: trim "%v" to "%v" because it is too long.`, v, string([]byte(v)[:consts.TaskCommLen]))
			}
			procNames = append(procNames, toProcessName(v))
		}
		return callback(f, procNames, overrideOutbound)
	}
}

func parsePrefixes(values []string) (cidrs []netip.Prefix, err error) {
	for _, value := range values {
		toParse := value
		if strings.LastIndexByte(value, '/') == -1 {
			toParse += "/32"
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
	return func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *Outbound) (err error) {
		var values []T
		for _, v := range paramValueGroup {
			val, err := strconv.ParseUint(v, 0, 8*size)
			if err != nil {
				return fmt.Errorf("cannot parse %v: %w", v, err)
			}
			values = append(values, T(val))
		}
		return callback(f, values, overrideOutbound)
	}
}
