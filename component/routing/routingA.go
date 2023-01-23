/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package routing

import (
	"fmt"
	"github.com/antlr/antlr4/runtime/Go/antlr"
	"github.com/v2rayA/RoutingA-dist/go/routingA"
)

func Parse(in string) (routingRules []RoutingRule, finalOutbound string, err error) {
	errorListener := NewConsoleErrorListener()
	lexer := routingA.NewroutingALexer(antlr.NewInputStream(in))
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(errorListener)
	input := antlr.NewCommonTokenStream(lexer, 0)

	parser := routingA.NewroutingAParser(input)
	parser.RemoveErrorListeners()
	parser.AddErrorListener(errorListener)
	parser.BuildParseTrees = true
	tree := parser.Start()

	walker := NewRoutingAWalker(parser)
	antlr.ParseTreeWalkerDefault.Walk(walker, tree)
	if errorListener.ErrorBuilder.Len() != 0 {
		return nil, "", fmt.Errorf("%v", errorListener.ErrorBuilder.String())
	}

	return walker.RoutingRules, walker.FinalOutbound, nil
}
