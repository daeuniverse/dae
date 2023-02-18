/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package outbound

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/config"
	"github.com/v2rayA/dae/pkg/config_parser"
	"strconv"
)

type DialerSelectionPolicy struct {
	Policy     consts.DialerSelectionPolicy
	FixedIndex int
}

func NewDialerSelectionPolicyFromGroupParam(param *config.GroupParam) (policy *DialerSelectionPolicy, err error) {
	switch val := param.Policy.(type) {
	case string:
		switch consts.DialerSelectionPolicy(val) {
		case consts.DialerSelectionPolicy_Random,
			consts.DialerSelectionPolicy_MinAverage10Latencies,
			consts.DialerSelectionPolicy_MinLastLatency:
			return &DialerSelectionPolicy{
				Policy: consts.DialerSelectionPolicy(val),
			}, nil
		case consts.DialerSelectionPolicy_Fixed:
			return nil, fmt.Errorf("%v need to specify node index", val)
		default:
			return nil, fmt.Errorf("unexpected policy: %v", val)
		}
	case []*config_parser.Function:
		if len(val) > 1 || len(val) == 0 {
			logrus.Debugf("%@", val)
			return nil, fmt.Errorf("policy should be exact 1 function: got %v", len(val))
		}
		f := val[0]
		switch consts.DialerSelectionPolicy(f.Name) {
		case consts.DialerSelectionPolicy_Fixed:
			// Should be like:
			// policy: fixed(0)
			if f.Not {
				return nil, fmt.Errorf("policy param does not support not operator: !%v()", f.Name)
			}
			if len(f.Params) > 1 || f.Params[0].Key != "" {
				return nil, fmt.Errorf(`invalid "%v" param format`, f.Name)
			}
			strIndex := f.Params[0].Val
			index, err := strconv.Atoi(strIndex)
			if len(f.Params) > 1 || f.Params[0].Key != "" {
				return nil, fmt.Errorf(`invalid "%v" param format: %w`, f.Name, err)
			}
			return &DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy(f.Name),
				FixedIndex: index,
			}, nil
		default:
			return nil, fmt.Errorf("unexpected policy func: %v", f.Name)
		}
	default:
		return nil, fmt.Errorf("unexpected param.Policy.(type): %T", val)
	}
}
