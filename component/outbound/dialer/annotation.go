/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"strconv"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

const (
	AnnotationKey_AddLatency = "add_latency"
	AnnotationKey_AddWeight  = "add_weight"
	maxAddWeight             = int64(^uint64(0)>>1) - 1
)

type Annotation struct {
	AddLatency time.Duration
	AddWeight  int64
}

func NewAnnotation(annotation []*config_parser.Param) (*Annotation, error) {
	var anno Annotation
	var addLatencySet bool
	var addWeightSet bool
	for _, param := range annotation {
		switch param.Key {
		case AnnotationKey_AddLatency:
			latency, err := time.ParseDuration(param.Val)
			if err != nil {
				return nil, fmt.Errorf("incorrect latency format: %w", err)
			}
			// Only the first setting is valid.
			if !addLatencySet {
				anno.AddLatency = latency
				addLatencySet = true
			}
		case AnnotationKey_AddWeight:
			weight, err := strconv.ParseInt(param.Val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("incorrect weight format: %w", err)
			}
			if weight < 0 {
				return nil, fmt.Errorf("incorrect weight value: effective weight must be positive")
			}
			if weight > maxAddWeight {
				return nil, fmt.Errorf("incorrect weight value: effective weight overflows int64")
			}
			// Only the first setting is valid.
			if !addWeightSet {
				anno.AddWeight = weight
				addWeightSet = true
			}
		default:
			return nil, fmt.Errorf("unknown filter annotation: %v", param.Key)
		}
	}
	return &anno, nil
}
