/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

// This file should trace https://github.com/daeuniverse/dae-config-dist/blob/main/dae_config.g4.

package config_parser

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/antlr/antlr4/runtime/Go/antlr/v4"
	"github.com/daeuniverse/dae-config-dist/go/dae_config"
	"github.com/sirupsen/logrus"
)

type Walker struct {
	*dae_config.Basedae_configListener
	parser antlr.Parser

	Sections []*Section

	hasLexerError bool
}

func NewWalker(parser antlr.Parser) *Walker {
	return &Walker{
		parser: parser,
	}
}

type paramParser struct {
	list []*Param
}

func getValueFromLiteral(literal *dae_config.LiteralContext) string {
	quote := literal.Quote_literal()
	if quote == nil {
		return literal.GetText()
	}
	text := quote.GetText()
	return text[1 : len(text)-1]
}

func (p *paramParser) parseParam(ctx *dae_config.ParameterContext) *Param {
	children := ctx.GetChildren()
	if len(children) == 3 {
		return &Param{
			Key: children[0].(*antlr.TerminalNodeImpl).GetText(),
			Val: getValueFromLiteral(children[2].(*dae_config.LiteralContext)),
		}
	} else if len(children) == 1 {
		return &Param{
			Key: "",
			Val: getValueFromLiteral(children[0].(*dae_config.LiteralContext)),
		}
	}
	panic("unexpected")
}
func (p *paramParser) parseNonEmptyParamList(ctx *dae_config.NonEmptyParameterListContext) {
	children := ctx.GetChildren()
	if len(children) == 3 {
		p.parseNonEmptyParamList(children[0].(*dae_config.NonEmptyParameterListContext))
		p.list = append(p.list, p.parseParam(children[2].(*dae_config.ParameterContext)))
	} else if len(children) == 1 {
		p.list = append(p.list, p.parseParam(children[0].(*dae_config.ParameterContext)))
	}
}

func (w *Walker) parseNonEmptyParamList(list *dae_config.NonEmptyParameterListContext) []*Param {
	paramParser := new(paramParser)
	paramParser.parseNonEmptyParamList(list)
	return paramParser.list
}

func (w *Walker) reportKeyUnsupportedError(ctx interface{}, keyName, funcName string) {
	w.ReportError(ctx, ErrorType_Unsupported, fmt.Sprintf("key %v in %v()", strconv.Quote(keyName), funcName))
}

type functionVerifier func(function *Function, ctx interface{}) bool

func (w *Walker) parseFunctionPrototype(ctx *dae_config.FunctionPrototypeContext, verifier functionVerifier) *Function {
	children := ctx.GetChildren()
	not := false
	offset := 0
	if len(children) == 0 {
		w.ReportError(ctx, ErrorType_Unsupported, "bad function prototype expression")
		return nil
	}
	if children[0].(*antlr.TerminalNodeImpl).GetText() == "!" {
		offset++
		not = true
	}
	if len(children) <= offset+2 {
		w.ReportError(ctx, ErrorType_Unsupported, "bad function prototype expression")
		return nil
	}
	funcName := children[offset+0].(*antlr.TerminalNodeImpl).GetText()
	paramList := children[offset+2].(*dae_config.OptParameterListContext)
	children = paramList.GetChildren()
	if len(children) == 0 {
		w.ReportError(ctx, ErrorType_Unsupported, "empty parameter list")
		return nil
	}
	nonEmptyParamList := children[0].(*dae_config.NonEmptyParameterListContext)
	params := w.parseNonEmptyParamList(nonEmptyParamList)
	f := &Function{
		Name:   funcName,
		Not:    not,
		Params: params,
	}
	// Verify function name and param keys.
	if verifier != nil && !verifier(f, ctx) {
		return nil
	}
	return f
}

func (w *Walker) ReportError(ctx interface{}, errorType ErrorType, target ...string) {
	if _, ok := ctx.(*antlr.ErrorNodeImpl); ok {
		return
	}
	//debug.PrintStack()
	bCtx := BaseContext(ctx)
	tgt := strconv.Quote(bCtx.GetStart().GetText())
	if len(target) != 0 {
		tgt = target[0]
	}
	if errorType == ErrorType_NotSet {
		w.parser.NotifyErrorListeners(fmt.Sprintf("%v %v.", tgt, errorType), nil, nil)
		return
	}
	w.parser.NotifyErrorListeners(fmt.Sprintf("%v %v.", tgt, errorType), bCtx.GetStart(), nil)
}

func (w *Walker) declarationFunctionVerifier(function *Function, ctx interface{}) bool {
	//if function.Not {
	//	w.ReportError(ctx, ErrorType_Unsupported, "Not operator in param declaration")
	//	return false
	//}
	return true
}

type literalExpressionParser struct {
	literals []string
}

func (p *literalExpressionParser) Parse(ctx *dae_config.LiteralExpressionContext) {
	children := ctx.GetChildren()
	p.literals = append(p.literals, getValueFromLiteral(children[0].(*dae_config.LiteralContext)))
	if len(children) == 1 {
		return
	}
	p.Parse(children[2].(*dae_config.LiteralExpressionContext))
}

func (w *Walker) parseDeclaration(ctx dae_config.IDeclarationContext) *Param {
	children := ctx.GetChildren()
	if len(children) < 3 {
		w.ReportError(ctx, ErrorType_Unsupported, "bad declaration expression")
		return nil
	}
	key := children[0].(*antlr.TerminalNodeImpl).GetText()
	switch valueCtx := children[2].(type) {
	case *dae_config.LiteralExpressionContext:
		parser := literalExpressionParser{}
		parser.Parse(valueCtx)
		return &Param{
			Key: key,
			Val: strings.Join(parser.literals, ","), // TODO: Do we just check grammar and trim spaces and put it back?
		}
	case *dae_config.FunctionPrototypeExpressionContext:
		andFunctions := w.parseFunctionPrototypeExpression(valueCtx, w.declarationFunctionVerifier)
		if andFunctions == nil {
			return nil
		}
		return &Param{
			Key:          key,
			AndFunctions: andFunctions,
		}
	default:
		w.ReportError(valueCtx, ErrorType_Unsupported)
		return nil
	}
}

func (w *Walker) parseFunctionPrototypeExpression(ctx dae_config.IFunctionPrototypeExpressionContext, verifier functionVerifier) (andFunctions []*Function) {
	children := ctx.GetChildren()
	for _, child := range children {
		// And rules.
		switch child := child.(type) {
		case *dae_config.FunctionPrototypeContext:
			function := w.parseFunctionPrototype(child, verifier)
			if function == nil {
				return
			}
			andFunctions = append(andFunctions, function)
		case *dae_config.FunctionPrototypeExpressionContext:
			funcs := w.parseFunctionPrototypeExpression(child, verifier)
			if funcs != nil {
				andFunctions = append(andFunctions, funcs...)
			}
		case *antlr.TerminalNodeImpl:
		default:
			w.ReportError(child, ErrorType_Unsupported)
			return nil
		}
	}
	return andFunctions
}

func (w *Walker) parseRoutingRule(ctx dae_config.IRoutingRuleContext) *RoutingRule {
	children := ctx.GetChildren()
	if len(children) < 3 {
		w.ReportError(ctx, ErrorType_Unsupported, "bad routing rule expression")
		return nil
	}
	//logrus.Debugln(ctx.GetText(), children)
	functionList, ok := children[0].(*dae_config.FunctionPrototypeExpressionContext)
	if !ok {
		w.ReportError(ctx, ErrorType_Unsupported, "not *FunctionPrototypeExpressionContext: "+ctx.GetText())
		return nil
	}
	// Parse functions.
	andFunctions := w.parseFunctionPrototypeExpression(functionList, nil)

	// Parse outbound.
	outboundExpr := children[2].(*dae_config.OutboundExprContext)
	var outbound *Function
	if literal := outboundExpr.Bare_literal(); literal != nil {
		outbound = &Function{Name: literal.GetText()}
	} else if f := outboundExpr.FunctionPrototype(); f != nil {
		outbound = w.parseFunctionPrototype(f.(*dae_config.FunctionPrototypeContext), nil)
	} else {
		panic("unknown outboundExpr")
	}
	return &RoutingRule{
		AndFunctions: andFunctions,
		Outbound:     *outbound,
	}
}

type routingRuleOrDeclarationOrLiteralOrExpressionListParser struct {
	Items  []*Item
	Walker *Walker
}

func (p *routingRuleOrDeclarationOrLiteralOrExpressionListParser) Parse(ctx dae_config.IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext) {
	for _, elem := range ctx.GetChildren() {
		switch elem := elem.(type) {
		case dae_config.IRoutingRuleContext:
			rule := p.Walker.parseRoutingRule(elem)
			if rule == nil {
				return
			}
			p.Items = append(p.Items, NewRoutingRuleItem(rule))
		case dae_config.IDeclarationContext:
			param := p.Walker.parseDeclaration(elem)
			if param == nil {
				return
			}
			p.Items = append(p.Items, NewParamItem(param))
		case *dae_config.LiteralContext:
			p.Items = append(p.Items, NewParamItem(&Param{
				Key: "",
				Val: getValueFromLiteral(elem),
			}))
		case dae_config.IExpressionContext:
			section := p.Walker.parseExpression(elem)
			if section == nil {
				return
			}
			p.Items = append(p.Items, NewSectionItem(section))
		case dae_config.IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext:
			p.Parse(elem)
		default:
			logrus.Debugf("? %T", elem)
			p.Walker.ReportError(elem, ErrorType_Unsupported)
			return
		}
	}
}
func (w *Walker) parseRoutingRuleOrDeclarationOrLiteralOrExpressionListContext(ctx dae_config.IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext) []*Item {
	parser := routingRuleOrDeclarationOrLiteralOrExpressionListParser{
		Items:  nil,
		Walker: w,
	}
	parser.Parse(ctx)
	return parser.Items

}

func (w *Walker) parseExpression(exp dae_config.IExpressionContext) *Section {
	children := exp.GetChildren()
	name := children[0].(*antlr.TerminalNodeImpl).GetText()
	list := children[2].(dae_config.IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext)
	items := w.parseRoutingRuleOrDeclarationOrLiteralOrExpressionListContext(list)
	return &Section{
		Name:  name,
		Items: items,
	}
}

func (w *Walker) VisitErrorNode(node antlr.ErrorNode) {
	w.hasLexerError = true
}

func (w *Walker) EnterProgramStructureBlcok(ctx *dae_config.ProgramStructureBlcokContext) {
	if w.hasLexerError {
		return
	}
	section := w.parseExpression(ctx.Expression())
	if section == nil {
		return
	}
	w.Sections = append(w.Sections, section)
}
