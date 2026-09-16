/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"fmt"
	"github.com/antlr/antlr4/runtime/Go/antlr/v4"
	"github.com/daeuniverse/dae-config-dist/go/dae_config"
)

func Parse(in string) (sections []*Section, err error) {
	defer func() {
		if r := recover(); r != nil {
			// The walker contains defensive panics and bare type assertions
			// that ANTLR error-recovery trees can trip. A malformed config
			// must surface as a parse error instead of crashing the process.
			sections = nil
			err = fmt.Errorf("failed to parse config: unexpected parser state: %v", r)
		}
	}()
	errorListener := NewConsoleErrorListener()
	lexer := dae_config.Newdae_configLexer(antlr.NewInputStream(in))
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(errorListener)
	input := antlr.NewCommonTokenStream(lexer, 0)

	parser := dae_config.Newdae_configParser(input)
	parser.RemoveErrorListeners()
	parser.AddErrorListener(errorListener)
	parser.BuildParseTrees = true
	tree := parser.Start()

	walker := NewWalker(parser)
	antlr.ParseTreeWalkerDefault.Walk(walker, tree)
	if errorListener.ErrorBuilder.Len() != 0 {
		return nil, fmt.Errorf("%v", errorListener.ErrorBuilder.String())
	}

	return walker.Sections, nil
}
