/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"math"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestNewAnnotation_AddLatencyFirstSettingWins(t *testing.T) {
	annotation, err := NewAnnotation([]*config_parser.Param{
		{Key: AnnotationKey_AddLatency, Val: "5s"},
		{Key: AnnotationKey_AddLatency, Val: "9s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if annotation.AddLatency != 5*time.Second {
		t.Fatalf("unexpected add_latency: %v", annotation.AddLatency)
	}
}

func TestNewAnnotation_AddLatencyFirstSettingWinsWhenFirstIsZero(t *testing.T) {
	annotation, err := NewAnnotation([]*config_parser.Param{
		{Key: AnnotationKey_AddLatency, Val: "0s"},
		{Key: AnnotationKey_AddLatency, Val: "5s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if annotation.AddLatency != 0 {
		t.Fatalf("unexpected add_latency: %v", annotation.AddLatency)
	}
}

func TestNewAnnotation_AddWeight(t *testing.T) {
	annotation, err := NewAnnotation([]*config_parser.Param{{Key: AnnotationKey_AddWeight, Val: "3"}})
	if err != nil {
		t.Fatal(err)
	}
	if annotation.AddWeight != 3 {
		t.Fatalf("unexpected add_weight: %v", annotation.AddWeight)
	}
}

func TestNewAnnotation_AddWeightRejectsNonPositiveEffectiveWeight(t *testing.T) {
	for _, val := range []string{"-1", "-2"} {
		_, err := NewAnnotation([]*config_parser.Param{{Key: AnnotationKey_AddWeight, Val: val}})
		if err == nil {
			t.Fatalf("expected add_weight=%s to fail", val)
		}
	}
}

func TestNewAnnotation_AddWeightRejectsInvalidNumber(t *testing.T) {
	_, err := NewAnnotation([]*config_parser.Param{{Key: AnnotationKey_AddWeight, Val: "abc"}})
	if err == nil {
		t.Fatal("expected invalid weight to fail")
	}
}

func TestNewAnnotation_AddWeightRejectsOverflowingValue(t *testing.T) {
	_, err := NewAnnotation([]*config_parser.Param{{Key: AnnotationKey_AddWeight, Val: "9223372036854775807"}})
	if err == nil {
		t.Fatal("expected overflowing weight to fail")
	}
}

func TestNewAnnotation_AddWeightAcceptsLargestSafeValue(t *testing.T) {
	annotation, err := NewAnnotation([]*config_parser.Param{{Key: AnnotationKey_AddWeight, Val: "9223372036854775806"}})
	if err != nil {
		t.Fatal(err)
	}
	if annotation.AddWeight != math.MaxInt64-1 {
		t.Fatalf("unexpected add_weight: %v", annotation.AddWeight)
	}
}

func TestNewAliveDialerSet_AddWeightAcceptsLargestSafeEffectiveWeight(t *testing.T) {
	dialers := []*Dialer{{}}
	annotations := []*Annotation{{AddWeight: math.MaxInt64 - 1}}
	set := NewAliveDialerSet(
		nil,
		"test-group",
		nil,
		0,
		consts.DialerSelectionPolicy_Random,
		dialers,
		annotations,
		func(bool) {},
		false,
	)
	if got := set.dialerToWeight[dialers[0]]; got != math.MaxInt64 {
		t.Fatalf("unexpected effective weight: %v", got)
	}
}

func TestNewAnnotation_AddWeightFirstSettingWins(t *testing.T) {
	annotation, err := NewAnnotation([]*config_parser.Param{
		{Key: AnnotationKey_AddWeight, Val: "5"},
		{Key: AnnotationKey_AddWeight, Val: "9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if annotation.AddWeight != 5 {
		t.Fatalf("unexpected add_weight: %v", annotation.AddWeight)
	}
}

func TestNewAnnotation_AddWeightFirstSettingWinsWhenFirstIsZero(t *testing.T) {
	annotation, err := NewAnnotation([]*config_parser.Param{
		{Key: AnnotationKey_AddWeight, Val: "0"},
		{Key: AnnotationKey_AddWeight, Val: "9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if annotation.AddWeight != 0 {
		t.Fatalf("unexpected add_weight: %v", annotation.AddWeight)
	}
}
