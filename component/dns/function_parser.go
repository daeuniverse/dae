/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TypeParserFactory(callback func(f *config_parser.Function, types []uint16, overrideOutbound *routing.Outbound) (err error)) routing.FunctionParser {
	return func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *routing.Outbound) (err error) {
		var types []uint16
		for _, v := range paramValueGroup {
			if t, ok := dnsmessage.StringToType[strings.ToUpper(v)]; ok {
				types = append(types, t)
				continue
			}
			if val, err := strconv.ParseUint(v, 0, 16); err == nil {
				types = append(types, uint16(val))
				continue
			}
			return fmt.Errorf("unknown DNS request type: %v", v)
		}
		return callback(f, types, overrideOutbound)
	}
}
