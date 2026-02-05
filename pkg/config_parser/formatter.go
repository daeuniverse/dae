/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"fmt"
	"strings"

	"github.com/antlr4-go/antlr/v4"
	"github.com/daeuniverse/dae-config-dist/go/dae_config"
)

type Formatter struct {
	*dae_config.Basedae_configListener
	out    strings.Builder
	tokens *antlr.CommonTokenStream

	indentStr   string
	indentLevel int

	// State flags to control spacing between tokens
	requireSpace bool

	// Stack to track current rule context
	stack []antlr.ParserRuleContext
}

func NewFormatter(indent string, tokens *antlr.CommonTokenStream) *Formatter {
	return &Formatter{
		indentStr: indent,
		tokens:    tokens,
	}
}

func isTypeOf[T any](ctx any) bool {
	_, ok := ctx.(T)
	return ctx != nil && ok
}

func (f *Formatter) GetResult() string {
	return strings.TrimSpace(f.out.String())
}

func (f *Formatter) push(ctx antlr.ParserRuleContext) {
	f.stack = append(f.stack, ctx)
}

func (f *Formatter) pop() {
	if len(f.stack) > 0 {
		f.stack = f.stack[:len(f.stack)-1]
	}
}

func (f *Formatter) peek() antlr.ParserRuleContext {
	if len(f.stack) == 0 {
		return nil
	}
	return f.stack[len(f.stack)-1]
}

// ensureNewLine ensures the output ends with a newline.
func (f *Formatter) ensureNewLine() {
	str := f.out.String()
	if len(str) > 0 && !strings.HasSuffix(str, "\n") {
		f.out.WriteRune('\n')
	}
}

// ensureSpace ensures the output ends with a space (unless it ends with newline).
func (f *Formatter) ensureSpace() {
	str := f.out.String()
	if len(str) > 0 && !strings.HasSuffix(str, " ") && !strings.HasSuffix(str, "\n") {
		f.out.WriteRune(' ')
	}
}

func (f *Formatter) writeIndent() {
	f.out.WriteString(strings.Repeat(f.indentStr, f.indentLevel))
}

// printHidden prints hidden tokens (comments) preceding the current token.
// Returns true if a newline was encountered in the hidden tokens (even if whitespace was skipped).
func (f *Formatter) printHidden(tokenIndex int) bool {
	hidden := f.tokens.GetHiddenTokensToLeft(tokenIndex, antlr.TokenHiddenChannel)
	hasNewline := false

	for _, t := range hidden {
		text := t.GetText()
		trimmed := strings.TrimSpace(text)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") {
			isLineComment := strings.HasPrefix(trimmed, "#")
			isBlockComment := strings.HasPrefix(trimmed, "/*")
			if hasNewline {
				f.ensureNewLine()
				f.writeIndent()
			} else {
				f.ensureSpace()
			}

			if isBlockComment {
				// Normalize block comments
				lines := strings.Split(text, "\n")
				f.out.WriteString(lines[0])
				for i := 1; i < len(lines); i++ {
					f.out.WriteRune('\n')
					f.writeIndent()
					f.out.WriteString(strings.TrimSpace(lines[i]))
				}
			} else if isLineComment {
				// Use trimmed text directly to preserve user formatting (e.g. `#####`)
				// but ensure indentation.
				// However, if we use trimmed, we lose valid indentation inside the comment?
				// Line comments usually don't have "indentation" except space after #.
				// If user wrote `#    code`, trimmed is `#    code`.
				// If user wrote `   # code`, trimmed is `# code`.
				// So `trimmed` is safe.
				f.out.WriteString(trimmed)
			}

			if isLineComment {
				f.out.WriteRune('\n')
				hasNewline = true
			}
		} else {
			// Whitespace token
			newlines := strings.Count(text, "\n")
			if newlines > 0 {
				hasNewline = true
				// If we have multiple newlines, preserve one empty line (double newline).
				// Check if we already have a double newline at end of out?
				// Only if we haven't printed it yet.
				// This is tricky.
				// If newlines > 1, and we are not at start of file?
				if newlines > 1 {
					// Ensure we have at least 2 newlines if we aren't at start
					if f.out.Len() > 0 && !strings.HasSuffix(f.out.String(), "\n\n") {
						f.ensureNewLine()
						f.out.WriteRune('\n')
					}
				}
			}
		}
	}
	return hasNewline
}

func (f *Formatter) EnterEveryRule(ctx antlr.ParserRuleContext) {
	f.push(ctx)
}

func (f *Formatter) ExitEveryRule(ctx antlr.ParserRuleContext) {
	f.pop()
}

func (f *Formatter) EnterOptParameterList(ctx *dae_config.OptParameterListContext) {
	f.indentLevel++
}

func (f *Formatter) ExitOptParameterList(ctx *dae_config.OptParameterListContext) {
	f.indentLevel--
}

func (f *Formatter) VisitTerminal(node antlr.TerminalNode) {
	symbol := node.GetSymbol()
	idx := symbol.GetTokenIndex()
	text := node.GetText()

	fmt.Printf("Terminal: %q (Type: %d)\n", text, symbol.GetTokenType())

	// 1. Handle EOF
	if symbol.GetTokenType() == antlr.TokenEOF {
		f.printHidden(idx)
		return
	}

	// 0. Pre-check for Top Level Expression Start
	for i := len(f.stack) - 1; i >= 0; i-- {
		ctx := f.stack[i]
		if ctx.GetStart() == symbol && isTypeOf[dae_config.IExpressionContext](ctx) && f.isTopLevelExpression() && idx > 0 {
			f.ensureNewLine()
			f.out.WriteRune('\n')
		}
	}

	// 2. Print hidden tokens
	hasNewlineInHidden := f.printHidden(idx)

	// 3. Determine formatting BEFORE the token (based on stack)
	for i := len(f.stack) - 1; i >= 0; i-- {
		ctx := f.stack[i]
		var prev antlr.ParserRuleContext
		if i > 0 {
			prev = f.stack[i-1]
		}

		if ctx.GetStart() == symbol {
			switch ctx.(type) {
			case dae_config.IRoutingRuleContext:
				f.ensureNewLine()
				f.writeIndent()
			case dae_config.IDeclarationContext:
				if isTypeOf[dae_config.IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext](prev) {
					f.ensureNewLine()
					f.writeIndent()
				}
			case dae_config.ILiteralContext:
				if isTypeOf[dae_config.IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext](prev) {
					f.ensureNewLine()
					f.writeIndent()
				}
			case dae_config.IExpressionContext:
				if isTypeOf[dae_config.IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext](prev) {
					f.ensureNewLine()
					f.writeIndent()
				}
			case dae_config.IOptAnnotationContext:
				f.ensureSpace()
			}
		}
	}

	// Logic for newlines in parameter lists
	if hasNewlineInHidden {
		if f.isInParameterList() {
			f.ensureNewLine()
			f.writeIndent()
		}
	}

	// Logic for spacing
	top := f.peek()
	switch text {
	case "&&":
		f.ensureSpace()
	case "{":
		if isTypeOf[dae_config.IExpressionContext](top) {
			f.ensureSpace()
		}
	}

	if f.requireSpace && !strings.HasSuffix(f.out.String(), "\n") {
		f.ensureSpace()
	}
	f.requireSpace = false

	// Specific token handling
	switch text {
	case "}":
		f.indentLevel--
		if f.indentLevel < 0 {
			f.indentLevel = 0
		}
		f.ensureNewLine()
		f.writeIndent()
	case "->":
		f.ensureSpace()
	}

	// 4. Print the token
	f.out.WriteString(text)

	// 5. Determine formatting AFTER the token
	switch text {
	case "{":
		if isTypeOf[dae_config.IExpressionContext](top) {
			f.indentLevel++
			f.ensureNewLine()
		}
	case ":":
		// Allow space if block declaration (normal key-val) OR in Annotation
		// (Assuming we want spaces in annotations too)
		if f.isBlockDeclaration() {
			f.requireSpace = true
		}
	case ",":
		f.requireSpace = true
	case "->":
		f.requireSpace = true
	case "&&":
		f.requireSpace = true
	}
}

func (f *Formatter) isInParameterList() bool {
	for i := len(f.stack) - 1; i >= 0; i-- {
		switch f.stack[i].(type) {
		case dae_config.INonEmptyParameterListContext:
			return true
		case dae_config.IOptParameterListContext:
			return true
		case dae_config.IExpressionContext:
			return false
		case dae_config.IRoutingRuleContext:
			return false
		}
	}
	return false
}

func (f *Formatter) isTopLevelExpression() bool {
	count := 0
	for _, ctx := range f.stack {
		if isTypeOf[dae_config.IExpressionContext](ctx) {
			count++
		}
	}
	return count == 1
}

func (f *Formatter) isBlockDeclaration() bool {
	for i := len(f.stack) - 1; i >= 0; i-- {
		ctx := f.stack[i]
		var prev antlr.ParserRuleContext
		if i > 0 {
			prev = f.stack[i-1]
		}
		if isTypeOf[dae_config.IDeclarationContext](ctx) &&
			isTypeOf[dae_config.IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext](prev) {
			return true
		}
	}
	return false
}

func FormatWithIndent(in string, indent string) (string, error) {
	errorListener := NewConsoleErrorListener()

	lexer := dae_config.Newdae_configLexer(antlr.NewInputStream(in))
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(errorListener)
	input := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)

	parser := dae_config.Newdae_configParser(input)
	parser.RemoveErrorListeners()
	parser.AddErrorListener(errorListener)
	parser.BuildParseTrees = true
	tree := parser.Start_()

	formatter := NewFormatter(indent, input)
	antlr.ParseTreeWalkerDefault.Walk(formatter, tree)

	if errorListener.ErrorBuilder.Len() != 0 {
		return "", fmt.Errorf("%v", errorListener.ErrorBuilder.String())
	}
	return formatter.GetResult(), nil
}
