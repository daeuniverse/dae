/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

func TestParseFunctionOrString(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		f, err := ParseFunctionOrString("direct")
		require.NoError(t, err)
		require.Equal(t, "direct", f.Name)
	})

	t.Run("function", func(t *testing.T) {
		want := &config_parser.Function{Name: "proxy"}
		f, err := ParseFunctionOrString(want)
		require.NoError(t, err)
		require.Same(t, want, f)
	})

	t.Run("single_function_slice", func(t *testing.T) {
		want := &config_parser.Function{Name: "fallback"}
		f, err := ParseFunctionOrString([]*config_parser.Function{want})
		require.NoError(t, err)
		require.Same(t, want, f)
	})

	t.Run("invalid_slice_length", func(t *testing.T) {
		_, err := ParseFunctionOrString([]*config_parser.Function{
			{Name: "a"},
			{Name: "b"},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected exactly 1 function")
	})

	t.Run("unsupported_type", func(t *testing.T) {
		_, err := ParseFunctionOrString(123)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported function-or-string value type")
	})
}

func TestFunctionOrStringToFunctionPreservesLegacyPanicAPI(t *testing.T) {
	require.Equal(t, "direct", FunctionOrStringToFunction("direct").Name)
	require.Panics(t, func() {
		FunctionOrStringToFunction(123)
	})
}

func TestParseFunctionListOrString(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		fs, err := ParseFunctionListOrString("random")
		require.NoError(t, err)
		require.Len(t, fs, 1)
		require.Equal(t, "random", fs[0].Name)
	})

	t.Run("function", func(t *testing.T) {
		want := &config_parser.Function{Name: "fixed", Params: []*config_parser.Param{{Val: "1"}}}
		fs, err := ParseFunctionListOrString(want)
		require.NoError(t, err)
		require.Len(t, fs, 1)
		require.Same(t, want, fs[0])
	})

	t.Run("function_list", func(t *testing.T) {
		want := []*config_parser.Function{{Name: "random"}}
		fs, err := ParseFunctionListOrString(want)
		require.NoError(t, err)
		require.Equal(t, want, fs)
	})

	t.Run("unsupported_type", func(t *testing.T) {
		_, err := ParseFunctionListOrString(true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported function-list-or-string value type")
	})
}

func TestFunctionListOrStringToFunctionListPreservesLegacyPanicAPI(t *testing.T) {
	require.Equal(t, "random", FunctionListOrStringToFunctionList("random")[0].Name)
	require.Panics(t, func() {
		FunctionListOrStringToFunctionList(true)
	})
}

func TestPatchMustOutboundFallback(t *testing.T) {
	t.Run("converts_must_prefix_into_param", func(t *testing.T) {
		conf := &Config{
			Routing: Routing{
				Fallback: "must_proxy",
			},
		}

		err := patchMustOutbound(conf)
		require.NoError(t, err)

		f, err := ParseFunctionOrString(conf.Routing.Fallback)
		require.NoError(t, err)
		require.Equal(t, "proxy", f.Name)
		require.Len(t, f.Params, 1)
		require.Equal(t, "must", f.Params[0].Val)
	})

	t.Run("rejects_invalid_fallback_type", func(t *testing.T) {
		conf := &Config{
			Routing: Routing{
				Fallback: 123,
			},
		}

		err := patchMustOutbound(conf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported function-or-string value type")
	})
}
