/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
)

type DialerSelectionPolicy struct {
	Policy               consts.DialerSelectionPolicy
	FixedIndex           int
	FixedFallbackTimeout time.Duration // 节点超时时间
	FixedFallbackRetries int           // 超时重试次数
}

func NewDialerSelectionPolicyFromGroupParam(param *config.Group) (policy *DialerSelectionPolicy, err error) {
	fs, err := config.ParseFunctionListOrString(param.Policy)
	if err != nil {
		return nil, err
	}
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

	case consts.DialerSelectionPolicy_FixedWithFallback:

		if f.Not {
			return nil, fmt.Errorf("policy param does not support not operator: !%v()", f.Name)
		}
		if len(f.Params) < 1 || len(f.Params) > 3 {
			return nil, fmt.Errorf(`invalid "%v" param format: expected 1-3 params, got %v`, f.Name, len(f.Params))
		}
		// Parse index (required, first param)
		if f.Params[0].Key != "" {
			return nil, fmt.Errorf(`invalid "%v" param format: first param must be index (no key)`, f.Name)
		}
		index, err := strconv.Atoi(f.Params[0].Val)
		if err != nil {
			return nil, fmt.Errorf(`invalid "%v" param format: %w`, f.Name, err)
		}
		// Parse timeout (optional, second param, with unit suffix: ms/s/m)
		timeout := 3 * time.Second // default
		if len(f.Params) >= 2 {
			if f.Params[1].Key != "" {
				return nil, fmt.Errorf(`invalid "%v" param format: second param must be timeout (no key)`, f.Name)
			}
			timeout, err = parseDurationWithUnit(f.Params[1].Val)
			if err != nil {
				return nil, fmt.Errorf(`invalid "%v" param format: %w`, f.Name, err)
			}
		}
		// Parse retries (optional, third param)
		retries := 3 // default
		if len(f.Params) >= 3 {
			if f.Params[2].Key != "" {
				return nil, fmt.Errorf(`invalid "%v" param format: third param must be retry count (no key)`, f.Name)
			}
			retries, err = strconv.Atoi(f.Params[2].Val)
			if err != nil {
				return nil, fmt.Errorf(`invalid "%v" param format: retries must be an integer: %w`, f.Name, err)
			}
			if retries < 1 {
				return nil, fmt.Errorf(`invalid "%v" param format: retries must be >= 1`, f.Name)
			}
		}
		return &DialerSelectionPolicy{
			Policy:               consts.DialerSelectionPolicy_FixedWithFallback,
			FixedIndex:           index,
			FixedFallbackTimeout: timeout,
			FixedFallbackRetries: retries,
		}, nil

	default:
		return nil, fmt.Errorf("unexpected policy: %v", f.Name)
	}
}

// parseDurationWithUnit parses a duration string with optional unit suffix.
// Supported: "ms" (milliseconds), "s" (seconds), "m" (minutes).
// No suffix defaults to seconds for backward compatibility.
// Examples: "500ms", "5s", "2m", "10".
func parseDurationWithUnit(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}

	// Check "ms" first (must precede "s" check)
	if strings.HasSuffix(s, "ms") {
		val, err := strconv.ParseFloat(strings.TrimSuffix(s, "ms"), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return time.Duration(val * float64(time.Millisecond)), nil
	}

	// "s" suffix
	if strings.HasSuffix(s, "s") {
		val, err := strconv.ParseFloat(strings.TrimSuffix(s, "s"), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return time.Duration(val * float64(time.Second)), nil
	}

	// "m" suffix
	if strings.HasSuffix(s, "m") {
		val, err := strconv.ParseFloat(strings.TrimSuffix(s, "m"), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return time.Duration(val * float64(time.Minute)), nil
	}

	// No suffix: treat as seconds (backward compatible)
	val, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	return time.Duration(val * float64(time.Second)), nil
}
