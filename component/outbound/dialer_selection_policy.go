/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"fmt"
	"strconv"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
)

type DialerSelectionPolicy struct {
	Policy     consts.DialerSelectionPolicy
	FixedIndex int
}

func NewDialerSelectionPolicyFromGroupParam(param *config.Group) (policy *DialerSelectionPolicy, err error) {
	fs := config.FunctionListOrStringToFunctionList(param.Policy)
	if len(fs) > 1 || len(fs) == 0 {
		return nil, fmt.Errorf("policy should be exact 1 function: got %v", len(fs))
	}
	f := fs[0]
	switch fName := consts.DialerSelectionPolicy(f.Name); fName {
	case consts.DialerSelectionPolicy_Random,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		return &DialerSelectionPolicy{
			Policy: fName,
		}, nil
	case consts.DialerSelectionPolicy_Fixed:

		if f.Not {
			return nil, fmt.Errorf("policy param does not support not operator: !%v()", f.Name)
		}
		if len(f.Params) != 1 || f.Params[0].Key != "" {
			return nil, fmt.Errorf(`invalid "%v" param format`, f.Name)
		}
		strIndex := f.Params[0].Val
		index, err := strconv.Atoi(strIndex)
		if err != nil {
			return nil, fmt.Errorf(`invalid "%v" param format: %w`, f.Name, err)
		}
		return &DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy(f.Name),
			FixedIndex: index,
		}, nil

	default:
		return nil, fmt.Errorf("unexpected policy: %v", f.Name)
	}
}
