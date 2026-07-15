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
	FixedFallbackTimeout time.Duration                // 节点超时时间
	FixedFallbackRetries int                          // 超时重试次数
	FallbackPolicy       consts.DialerSelectionPolicy // 重试耗尽后的回退策略，默认 min_moving_avg
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
		if len(f.Params) < 1 || len(f.Params) > 4 {
			return nil, fmt.Errorf(`invalid "%v" param format: expected 1-4 params, got %v`, f.Name, len(f.Params))
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
		// Parse retries (optional, third param). Default 3. 0 means the node
		// falls back immediately on first failure with no background retry
		// (matches the canonical "retries<=0 = do not retry" semantics).
		retries := 3 // default
		if len(f.Params) >= 3 {
			if f.Params[2].Key != "" {
				return nil, fmt.Errorf(`invalid "%v" param format: third param must be retry count (no key)`, f.Name)
			}
			retries, err = strconv.Atoi(f.Params[2].Val)
			if err != nil {
				return nil, fmt.Errorf(`invalid "%v" param format: retries must be an integer: %w`, f.Name, err)
			}
			if retries < 0 {
				return nil, fmt.Errorf(`invalid "%v" param format: retries must be >= 0`, f.Name)
			}
		}
		// Parse fallback policy (optional, fourth param)
		fallbackPolicy := consts.DialerSelectionPolicy_MinMovingAverageLatencies // default
		if len(f.Params) >= 4 {
			if f.Params[3].Key != "" {
				return nil, fmt.Errorf(`invalid "%v" param format: fourth param must be fallback policy name (no key)`, f.Name)
			}
			fp, err := parsePolicyName(f.Params[3].Val)
			if err != nil {
				return nil, fmt.Errorf(`invalid "%v" param format: fallback policy: %w`, f.Name, err)
			}
			fallbackPolicy = fp
		}
		return &DialerSelectionPolicy{
			Policy:               consts.DialerSelectionPolicy_FixedWithFallback,
			FixedIndex:           index,
			FixedFallbackTimeout: timeout,
			FixedFallbackRetries: retries,
			FallbackPolicy:       fallbackPolicy,
		}, nil

	default:
		return nil, fmt.Errorf("unexpected policy: %v", f.Name)
	}
}

// parsePolicyName maps a policy name string to the corresponding DialerSelectionPolicy constant.
// Supported fallback policies: random, min_moving_avg, min_last_latency, min_avg10.
// Fixed and fixed_fallback are not supported as fallback policies (would cause infinite recursion).
func parsePolicyName(s string) (consts.DialerSelectionPolicy, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "random":
		return consts.DialerSelectionPolicy_Random, nil
	case "min_moving_avg":
		return consts.DialerSelectionPolicy_MinMovingAverageLatencies, nil
	case "min_last_latency":
		return consts.DialerSelectionPolicy_MinLastLatency, nil
	case "min_avg10":
		return consts.DialerSelectionPolicy_MinAverage10Latencies, nil
	default:
		return consts.DialerSelectionPolicy(""), fmt.Errorf("unsupported fallback policy %q (supported: random, min_moving_avg, min_last_latency, min_avg10)", s)
	}
}

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
