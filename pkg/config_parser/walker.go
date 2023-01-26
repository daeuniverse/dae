/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package config_parser

import (
	"fmt"
	"github.com/antlr/antlr4/runtime/Go/antlr/v4"
	"github.com/v2rayA/dae-config-dist/go/dae_config"
	"log"
	"strconv"
)

type Walker struct {
	*dae_config.Basedae_configListener
	parser antlr.Parser

	Sections []*Section
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
		p.list = append(p.list, p.parseParam(children[2].(*dae_config.ParameterContext)))
		p.parseNonEmptyParamList(children[0].(*dae_config.NonEmptyParameterListContext))
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
	funcName := children[0].(*antlr.TerminalNodeImpl).GetText()
	paramList := children[2].(*dae_config.OptParameterListContext)
	children = paramList.GetChildren()
	if len(children) == 0 {
		w.ReportError(ctx, ErrorType_Unsupported, "empty parameter list")
		return nil
	}
	nonEmptyParamList := children[0].(*dae_config.NonEmptyParameterListContext)
	params := w.parseNonEmptyParamList(nonEmptyParamList)
	f := &Function{
		Name:   funcName,
		Params: params,
	}
	// Verify function name and param keys.
	if verifier != nil && !verifier(f, ctx) {
		return nil
	}
	return f
}

func (w *Walker) ReportError(ctx interface{}, errorType ErrorType, target ...string) {
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

func (w *Walker) parseDeclaration(ctx dae_config.IDeclarationContext) *Param {
	children := ctx.GetChildren()
	key := children[0].(*antlr.TerminalNodeImpl).GetText()
	switch valueCtx := children[2].(type) {
	case *dae_config.LiteralContext:
		value := getValueFromLiteral(valueCtx)
		return &Param{
			Key: key,
			Val: value,
		}
	case *dae_config.FunctionPrototypeExpressionContext:
		andFunctions := w.parseFunctionPrototypeExpression(valueCtx, nil)
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
		if child, ok := child.(*dae_config.FunctionPrototypeContext); ok {
			function := w.parseFunctionPrototype(child, verifier)
			andFunctions = append(andFunctions, function)
		}
	}
	return andFunctions
}

func (w *Walker) parseRoutingRule(ctx dae_config.IRoutingRuleContext) *RoutingRule {
	children := ctx.GetChildren()
	//logrus.Debugln(ctx.GetText(), children)
	left, ok := children[0].(*dae_config.RoutingRuleLeftContext)
	if !ok {
		w.ReportError(ctx, ErrorType_Unsupported, "not *RoutingRuleLeftContext: "+ctx.GetText())
		return nil
	}
	outbound := children[2].(*dae_config.Bare_literalContext).GetText()
	// Parse functions.
	children = left.GetChildren()
	functionList, ok := children[1].(*dae_config.FunctionPrototypeExpressionContext)
	if !ok {
		w.ReportError(ctx, ErrorType_Unsupported, "not *FunctionPrototypeExpressionContext: "+ctx.GetText())
		return nil
	}
	andFunctions := w.parseFunctionPrototypeExpression(functionList, nil)
	return &RoutingRule{
		AndFunctions: andFunctions,
		Outbound:     outbound,
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
			log.Printf("? %v", elem.(*dae_config.ExpressionContext))
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

func (w *Walker) EnterProgramStructureBlcok(ctx *dae_config.ProgramStructureBlcokContext) {
	section := w.parseExpression(ctx.Expression())
	if section == nil {
		return
	}
	w.Sections = append(w.Sections, section)
}
