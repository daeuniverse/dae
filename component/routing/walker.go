/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package routing

import (
	"fmt"
	"foo/common/consts"
	"github.com/antlr/antlr4/runtime/Go/antlr"
	"github.com/v2rayA/RoutingA-dist/go/routingA"
	"strconv"
	"strings"
)

type RoutingAWalker struct {
	*routingA.BaseroutingAListener
	parser        antlr.Parser
	FinalOutbound string
	RoutingRules  []RoutingRule
}

func NewRoutingAWalker(parser antlr.Parser) *RoutingAWalker {
	return &RoutingAWalker{
		parser: parser,
	}
}

type RoutingRule struct {
	AndFunctions []*Function
	Outbound     string
}

func (r *RoutingRule) String(calcN bool) string {
	var builder strings.Builder
	var n int
	for _, f := range r.AndFunctions {
		if builder.Len() != 0 {
			builder.WriteString(" && ")
		}
		var paramBuilder strings.Builder
		n += len(f.Params)
		for _, p := range f.Params {
			if paramBuilder.Len() != 0 {
				paramBuilder.WriteString(", ")
			}
			if p.Key != "" {
				paramBuilder.WriteString(p.Key + ": " + p.Val)
			} else {
				paramBuilder.WriteString(p.Val)
			}
		}
		builder.WriteString(fmt.Sprintf("%v(%v)", f.Name, paramBuilder.String()))
	}
	builder.WriteString(" -> " + r.Outbound)
	if calcN {
		builder.WriteString(" [n = " + strconv.Itoa(n) + "]")
	}
	builder.WriteString("\n")
	return builder.String()
}

type Function struct {
	Name   string
	Params []*Param
}
type Param struct {
	Key string
	Val string
}
type paramParser struct {
	list []*Param
}

func getValueFromLiteral(literal *routingA.LiteralContext) string {
	quote := literal.Quote_literal()
	if quote == nil {
		return literal.GetText()
	}
	text := quote.GetText()
	return text[1 : len(text)-1]
}

func (p *paramParser) parseParam(ctx *routingA.ParameterContext) *Param {
	children := ctx.GetChildren()
	if len(children) == 3 {
		return &Param{
			Key: children[0].(*antlr.TerminalNodeImpl).GetText(),
			Val: getValueFromLiteral(children[2].(*routingA.LiteralContext)),
		}
	} else if len(children) == 1 {
		return &Param{
			Key: "",
			Val: getValueFromLiteral(children[0].(*routingA.LiteralContext)),
		}
	}
	panic("unexpected")
}
func (p *paramParser) parseNonEmptyParamList(ctx *routingA.NonEmptyParameterListContext) {
	children := ctx.GetChildren()
	if len(children) == 3 {
		p.list = append(p.list, p.parseParam(children[2].(*routingA.ParameterContext)))
		p.parseNonEmptyParamList(children[0].(*routingA.NonEmptyParameterListContext))
	} else if len(children) == 1 {
		p.list = append(p.list, p.parseParam(children[0].(*routingA.ParameterContext)))
	}
}

func (s *RoutingAWalker) parseNonEmptyParamList(list *routingA.NonEmptyParameterListContext) []*Param {
	paramParser := new(paramParser)
	paramParser.parseNonEmptyParamList(list)
	return paramParser.list
}

func (s *RoutingAWalker) reportKeyUnsupportedError(ctx interface{}, keyName, funcName string) {
	s.ReportError(ctx, ErrorType_Unsupported, fmt.Sprintf("key %v in %v()", strconv.Quote(keyName), funcName))
}

func (s *RoutingAWalker) parseFunctionPrototype(ctx *routingA.FunctionPrototypeContext) *Function {
	children := ctx.GetChildren()
	funcName := children[0].(*antlr.TerminalNodeImpl).GetText()
	paramList := children[2].(*routingA.ParameterListContext)
	children = paramList.GetChildren()
	if len(children) == 0 {
		s.ReportError(ctx, ErrorType_Unsupported, "empty parameter list")
		return nil
	}
	nonEmptyParamList := children[0].(*routingA.NonEmptyParameterListContext)
	params := s.parseNonEmptyParamList(nonEmptyParamList)
	// Validate function name and param keys.
	for _, param := range params {
		switch funcName {
		case "domain":
			switch param.Key {
			case "", "domain", consts.RoutingDomain_Suffix,
				consts.RoutingDomain_Keyword,
				"contains",
				consts.RoutingDomain_Full,
				consts.RoutingDomain_Regex,
				"geosite":
			default:
				s.reportKeyUnsupportedError(ctx, param.Key, funcName)
				return nil
			}
		case "ip":
			switch param.Key {
			case "",
				"geoip":
			default:
				s.reportKeyUnsupportedError(ctx, param.Key, funcName)
				return nil
			}
		case "port", "source", "sourcePort", "network", "ipVersion":
			if param.Key != "" {
				s.reportKeyUnsupportedError(ctx, param.Key, funcName)
				return nil
			}
		default:
			s.ReportError(ctx, ErrorType_Unsupported)
			return nil
		}
	}
	return &Function{
		Name:   funcName,
		Params: params,
	}
}

func (s *RoutingAWalker) ReportError(ctx interface{}, errorType ErrorType, target ...string) {
	bCtx := BaseContext(ctx)
	tgt := strconv.Quote(bCtx.GetStart().GetText())
	if len(target) != 0 {
		tgt = target[0]
	}
	if errorType == ErrorType_NotSet {
		s.parser.NotifyErrorListeners(fmt.Sprintf("%v %v.", tgt, errorType), nil, nil)
		return
	}
	s.parser.NotifyErrorListeners(fmt.Sprintf("%v %v.", tgt, errorType), bCtx.GetStart(), nil)
}

func (s *RoutingAWalker) EnterDeclaration(ctx *routingA.DeclarationContext) {
	children := ctx.GetChildren()
	key := children[0].(*antlr.TerminalNodeImpl).GetText()
	switch valueCtx := children[2].(type) {
	case *routingA.LiteralContext:
		value := getValueFromLiteral(valueCtx)
		if key == "default" {
			s.FinalOutbound = value
		} else {
			s.ReportError(ctx, ErrorType_Unsupported)
			return
		}
	case *routingA.AssignmentExpressionContext:
		s.ReportError(valueCtx, ErrorType_Unsupported)
		return
	default:
		s.ReportError(valueCtx, ErrorType_Unsupported)
		return
	}
}

func (s *RoutingAWalker) EnterRoutingRule(ctx *routingA.RoutingRuleContext) {
	children := ctx.GetChildren()
	left, ok := children[0].(*routingA.FunctionPrototypeExpressionContext)
	if !ok {
		s.ReportError(ctx, ErrorType_Unsupported)
		return
	}
	outbound := children[2].(*routingA.Bare_literalContext).GetText()
	// Parse functions.
	var andFunctions []*Function
	children = left.GetChildren()
	for _, child := range children {
		// And rules.
		if child, ok := child.(*routingA.FunctionPrototypeContext); ok {
			function := s.parseFunctionPrototype(child)
			andFunctions = append(andFunctions, function)
		}
	}
	s.RoutingRules = append(s.RoutingRules, RoutingRule{
		AndFunctions: andFunctions,
		Outbound:     outbound,
	})
}

func (s *RoutingAWalker) EnterRoutingRuleOrDeclarationList(ctx *routingA.RoutingRuleOrDeclarationListContext) {
	s.ReportError(ctx, ErrorType_Unsupported)
}

func (s *RoutingAWalker) ExitStart(ctx *routingA.StartContext) {
	if s.FinalOutbound == "" {
		s.ReportError(ctx, ErrorType_NotSet, `"default"`)
	}
}
