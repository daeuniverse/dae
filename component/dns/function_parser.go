/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/dns/dnsmessage"
)

var typeNames = map[string]dnsmessage.Type{
	"A":     dnsmessage.TypeA,
	"NS":    dnsmessage.TypeNS,
	"CNAME": dnsmessage.TypeCNAME,
	"SOA":   dnsmessage.TypeSOA,
	"PTR":   dnsmessage.TypePTR,
	"MX":    dnsmessage.TypeMX,
	"TXT":   dnsmessage.TypeTXT,
	"AAAA":  dnsmessage.TypeAAAA,
	"SRV":   dnsmessage.TypeSRV,
	"OPT":   dnsmessage.TypeOPT,
	"WKS":   dnsmessage.TypeWKS,
	"HINFO": dnsmessage.TypeHINFO,
	"MINFO": dnsmessage.TypeMINFO,
	"AXFR":  dnsmessage.TypeAXFR,
	"ALL":   dnsmessage.TypeALL,
}

func TypeParserFactory(callback func(f *config_parser.Function, types []dnsmessage.Type, overrideOutbound *routing.Outbound) (err error)) routing.FunctionParser {
	return func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *routing.Outbound) (err error) {
		var types []dnsmessage.Type
		for _, v := range paramValueGroup {
			if t, ok := typeNames[strings.ToUpper(v)]; ok {
				types = append(types, t)
				continue
			}
			if val, err := strconv.ParseUint(v, 0, 16); err == nil {
				types = append(types, dnsmessage.Type(val))
				continue
			}
			return fmt.Errorf("unknown DNS request type: %v", v)
		}
		return callback(f, types, overrideOutbound)
	}
}
