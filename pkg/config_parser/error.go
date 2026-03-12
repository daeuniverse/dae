/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"fmt"
	"github.com/antlr/antlr4/runtime/Go/antlr/v4"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"
)

type ErrorType string

const (
	ErrorType_Unsupported ErrorType = "is not supported"
	ErrorType_NotSet      ErrorType = "is not set"
)

// Error hint messages for common configuration mistakes.
const (
	hintDigitPrefixDomain = `Hint: Domains or keys starting with a digit must be enclosed in quotes.
  Change: %s
  To:    '%s'
`
)

type ConsoleErrorListener struct {
	ErrorBuilder strings.Builder
}

func NewConsoleErrorListener() *ConsoleErrorListener {
	return &ConsoleErrorListener{}
}

// detectDigitPrefixDomainError checks if the error is caused by a domain/key starting
// with a digit without quotes. Returns a hint message if detected, empty string otherwise.
func (d *ConsoleErrorListener) detectDigitPrefixDomainError(msg, strLine string) string {
	// Fast path: only check for specific error patterns
	if !strings.Contains(msg, "mismatched input") &&
		!strings.Contains(msg, "expecting '}'") &&
		!strings.Contains(msg, "expecting") {
		return ""
	}

	// Skip if line already contains quotes (user knows to quote)
	if strings.Contains(strLine, "'") || strings.Contains(strLine, "\"") {
		return ""
	}

	// Skip if line doesn't contain colon (not a key:value pattern)
	if !strings.Contains(strLine, ":") {
		return ""
	}

	// Look for pattern: digit(s) followed by dot and colon (like "123.com:60")
	words := strings.Fields(strLine)
	for _, w := range words {
		if d.isDigitPrefixDomainPattern(w) {
			return fmt.Sprintf("\n\n"+hintDigitPrefixDomain, w, w)
		}
	}

	return ""
}

// isDigitPrefixDomainPattern checks if a string matches the pattern of a domain
// starting with a digit, like "123.com:60" or "123dns.com:53".
func (d *ConsoleErrorListener) isDigitPrefixDomainPattern(s string) bool {
	// Must contain both dot and colon
	if !strings.Contains(s, ".") || !strings.Contains(s, ":") {
		return false
	}

	// Check if first character is a digit
	if len(s) == 0 {
		return false
	}
	firstChar := s[0]
	if firstChar < '0' || firstChar > '9' {
		return false
	}

	return true
}

func (d *ConsoleErrorListener) SyntaxError(recognizer antlr.Recognizer, offendingSymbol any, line, column int, msg string, e antlr.RecognitionException) {
	// Do not accumulate errors.
	if d.ErrorBuilder.Len() > 0 {
		return
	}
	backtrack := min(column, 30)
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

	// Check for common error: domain starting with digit without quotes
	// This happens in fixed_domain_ttl, upstream, etc.
	// Example: "123.com:60" is parsed as number "123" then unexpected ":"
	hint := d.detectDigitPrefixDomainError(msg, strLine)

	d.ErrorBuilder.WriteString(fmt.Sprintf("%v%v\n%v%v: %v%v\n", starting, strLine, strings.Repeat(" ", offset), strings.Repeat("^", token.GetStop()-token.GetStart()+1), msg, hint))
}
func (d *ConsoleErrorListener) ReportAmbiguity(recognizer antlr.Parser, dfa *antlr.DFA, startIndex, stopIndex int, exact bool, ambigAlts *antlr.BitSet, configs antlr.ATNConfigSet) {
}

func (d *ConsoleErrorListener) ReportAttemptingFullContext(recognizer antlr.Parser, dfa *antlr.DFA, startIndex, stopIndex int, conflictingAlts *antlr.BitSet, configs antlr.ATNConfigSet) {
}

func (d *ConsoleErrorListener) ReportContextSensitivity(recognizer antlr.Parser, dfa *antlr.DFA, startIndex, stopIndex, prediction int, configs antlr.ATNConfigSet) {
}

func BaseContext(ctx any) (baseCtx *antlr.BaseParserRuleContext) {
	val := reflect.ValueOf(ctx)
	for val.Kind() == reflect.Pointer && val.Type() != reflect.TypeFor[*antlr.BaseParserRuleContext]() {
		val = val.Elem()
	}
	if val.Type() == reflect.TypeFor[*antlr.BaseParserRuleContext]() {
		baseCtx = val.Interface().(*antlr.BaseParserRuleContext)
	} else {
		baseCtxVal := val.FieldByName("BaseParserRuleContext")
		if !baseCtxVal.IsValid() {
			logrus.Debugf("%T", ctx)
			panic("has no field BaseParserRuleContext")
		}
		baseCtx = baseCtxVal.Interface().(*antlr.BaseParserRuleContext)
	}
	return baseCtx
}
