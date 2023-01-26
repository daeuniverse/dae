/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package config_parser

import (
	"fmt"
	"github.com/antlr/antlr4/runtime/Go/antlr/v4"
	"github.com/v2rayA/dae-config-dist/go/dae_config"
)

func Parse(in string) (sections []*Section, err error) {
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
