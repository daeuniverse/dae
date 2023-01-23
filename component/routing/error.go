/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package routing

import (
	"fmt"
	"github.com/antlr/antlr4/runtime/Go/antlr"
	"reflect"
	"strings"
)

type ErrorType string

const (
	ErrorType_Unsupported ErrorType = "is not supported"
	ErrorType_NotSet      ErrorType = "is not set"
)

type ConsoleErrorListener struct {
	ErrorBuilder strings.Builder
}

func NewConsoleErrorListener() *ConsoleErrorListener {
	return &ConsoleErrorListener{}
}

func (d *ConsoleErrorListener) SyntaxError(recognizer antlr.Recognizer, offendingSymbol interface{}, line, column int, msg string, e antlr.RecognitionException) {
	// Do not accumulate errors.
	if d.ErrorBuilder.Len() > 0 {
		return
	}
	backtrack := column
	if backtrack > 30 {
		backtrack = 30
	}
	starting := fmt.Sprintf("line %v:%v ", line, column)
	offset := len(starting) + backtrack
	var (
		simplyWrite bool
		token       antlr.Token
	)
	if offendingSymbol == nil {
		simplyWrite = true
	} else {
		token = offendingSymbol.(antlr.Token)
		simplyWrite = token.GetTokenType() == -1
	}
	if simplyWrite {
		d.ErrorBuilder.WriteString(fmt.Sprintf("%v%v", starting, msg))
		return
	}

	beginOfLine := token.GetStart() - backtrack
	strPeek := token.GetInputStream().GetText(beginOfLine, token.GetStop()+30)
	wrap := strings.IndexByte(strPeek, '\n')
	if wrap == -1 {
		wrap = token.GetStop() + 30
	} else {
		wrap += beginOfLine - 1
	}
	strLine := token.GetInputStream().GetText(beginOfLine, wrap)
	d.ErrorBuilder.WriteString(fmt.Sprintf("%v%v\n%v%v: %v\n", starting, strLine, strings.Repeat(" ", offset), strings.Repeat("^", token.GetStop()-token.GetStart()+1), msg))
}
func (d *ConsoleErrorListener) ReportAmbiguity(recognizer antlr.Parser, dfa *antlr.DFA, startIndex, stopIndex int, exact bool, ambigAlts *antlr.BitSet, configs antlr.ATNConfigSet) {
}

func (d *ConsoleErrorListener) ReportAttemptingFullContext(recognizer antlr.Parser, dfa *antlr.DFA, startIndex, stopIndex int, conflictingAlts *antlr.BitSet, configs antlr.ATNConfigSet) {
}

func (d *ConsoleErrorListener) ReportContextSensitivity(recognizer antlr.Parser, dfa *antlr.DFA, startIndex, stopIndex, prediction int, configs antlr.ATNConfigSet) {
}

func BaseContext(ctx interface{}) (baseCtx *antlr.BaseParserRuleContext) {
	val := reflect.ValueOf(ctx)
	for val.Kind() == reflect.Pointer && val.Type() != reflect.TypeOf(&antlr.BaseParserRuleContext{}) {
		val = val.Elem()
	}
	if val.Type() == reflect.TypeOf(&antlr.BaseParserRuleContext{}) {
		baseCtx = val.Interface().(*antlr.BaseParserRuleContext)
	} else {
		baseCtxVal := val.FieldByName("BaseParserRuleContext")
		if !baseCtxVal.IsValid() {
			panic("has no field BaseParserRuleContext")
		}
		baseCtx = baseCtxVal.Interface().(*antlr.BaseParserRuleContext)
	}
	return baseCtx
}
