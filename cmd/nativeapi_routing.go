/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/control"
)

func (p *nativeAPIProvider) RoutingTraceAvailable() bool {
	plane, err := p.activeControlPlane()
	return err == nil && plane.RoutingTraceAvailable()
}

func (p *nativeAPIProvider) TraceRouting(ctx context.Context, request nativeapi.RoutingTraceRequest) (nativeapi.RoutingTraceResponse, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.RoutingTraceResponse{}, err
	}
	plane, err := p.activeControlPlane()
	if err != nil {
		return nativeapi.RoutingTraceResponse{}, err
	}
	if !plane.RoutingTraceAvailable() {
		return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(503, "temporarily_unavailable", "routing trace snapshot is unavailable")
	}
	var network consts.L4ProtoType
	switch request.Input.Network {
	case "tcp":
		network = consts.L4ProtoType_TCP
	case "udp":
		network = consts.L4ProtoType_UDP
	default:
		return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(400, "invalid_request", "network must be tcp or udp")
	}
	dstIP, err := nativeTraceIP(request.Input.DstIP)
	if err != nil {
		return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(400, "invalid_request", "dst_ip must be a valid IP address")
	}
	srcIP, err := nativeTraceIP(request.Input.SrcIP)
	if err != nil {
		return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(400, "invalid_request", "src_ip must be a valid IP address")
	}
	input := control.RoutingTraceInput{
		Network: network,
		Domain:  request.Input.Domain,
		DstIP:   dstIP,
		DstPort: request.Input.DstPort,
		SrcIP:   srcIP,
		SrcPort: request.Input.SrcPort,
		Pname:   request.Input.Pname,
		Dscp:    request.Input.Dscp,
	}
	traceCtx, cancel := context.WithTimeout(ctx, time.Duration(nativeapi.RoutingTraceTimeoutMs)*time.Millisecond)
	defer cancel()
	evaluation, err := plane.TraceRouting(traceCtx, input)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(504, "temporarily_unavailable", "routing trace timed out")
		}
		return nativeapi.RoutingTraceResponse{}, err
	}
	stepCount := len(evaluation.Rules)
	for _, rule := range evaluation.Rules {
		stepCount += len(rule.Conditions)
	}
	if stepCount > nativeapi.MaxRoutingTraceRuleSteps {
		return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(422, "unsupported_value", "routing trace exceeds the configured rule-step limit")
	}

	snapshot := plane.SnapshotRoutingRules()
	response := nativeapi.RoutingTraceResponse{
		Mode:         "simulation",
		InstanceID:   p.status.snapshot().InstanceID,
		GenerationID: snapshot.GenerationID,
		ObservedAt:   time.Now().UTC().Format(time.RFC3339),
		Evaluations: []nativeapi.RoutingEvaluation{{
			DstIP:         evaluation.DstIP,
			Decision:      evaluation.Decision,
			Outbound:      evaluation.Outbound,
			MissingInputs: evaluation.MissingInputs,
			Rules:         make([]nativeapi.RuleEvaluation, 0, len(evaluation.Rules)),
		}},
		DNS: []nativeapi.SimulationDNSData{},
	}
	for _, rule := range evaluation.Rules {
		projected := nativeapi.RuleEvaluation{
			RuleID:        rule.RuleID,
			Expression:    rule.Expression,
			Result:        rule.Result,
			MissingInputs: rule.MissingInputs,
			Conditions:    make([]nativeapi.RuleCondition, 0, len(rule.Conditions)),
		}
		for _, condition := range rule.Conditions {
			projected.Conditions = append(projected.Conditions, nativeapi.RuleCondition{
				ID:            condition.ID,
				Expression:    condition.Expression,
				Result:        condition.Result,
				MissingInputs: condition.MissingInputs,
			})
		}
		response.Evaluations[0].Rules = append(response.Evaluations[0].Rules, projected)
	}
	return response, nil
}

func nativeTraceIP(value *string) (*netip.Addr, error) {
	if value == nil {
		return nil, nil
	}
	address, err := netip.ParseAddr(*value)
	if err != nil || address.Zone() != "" {
		return nil, strconv.ErrSyntax
	}
	return &address, nil
}

var _ nativeapi.RulesProvider = (*nativeAPIProvider)(nil)
