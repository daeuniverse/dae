/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	probeTimeout               = 5 * time.Second
	probeJobTimeout            = nativeapi.ProbeJobTimeoutMs * time.Millisecond
	probeMaxActiveJobs         = nativeapi.ProbeMaxActiveJobs
	probeMaxQueuedJobs         = nativeapi.ProbeMaxQueuedJobs
	probeMaxMembersPerJob      = nativeapi.ProbeMaxMembersPerJob
	probeMaxResultsPerJob      = nativeapi.ProbeMaxResultsPerJob
	probeGlobalRequestsPerMin  = nativeapi.ProbeRequestsPerMinute
	probeRateLimitWindow       = time.Minute
	probeRateLimitedRetryAfter = 60
)

// probeGate bounds how much probe work a client can queue and how fast it can
// submit it, so the advertised capabilities.limits are actually enforced.
type probeGate struct {
	mu          sync.Mutex
	inFlight    int
	windowStart time.Time
	windowCount int
	slots       chan struct{}
}

func newProbeGate() *probeGate {
	return &probeGate{slots: make(chan struct{}, probeMaxActiveJobs)}
}

// release undoes one reserve when the request never became a queued probe.
func (g *probeGate) release() {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.inFlight > 0 {
		g.inFlight--
	}
	g.mu.Unlock()
}

// reserve accounts for one accepted probe or reports why it cannot be queued.
func (g *probeGate) reserve(now time.Time) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.windowStart.IsZero() || now.Sub(g.windowStart) >= probeRateLimitWindow {
		g.windowStart = now
		g.windowCount = 0
	}
	if g.windowCount >= probeGlobalRequestsPerMin {
		return &nativeapi.APIError{
			Status:            429,
			Code:              "rate_limited",
			Message:           "probe request rate limit exceeded",
			RetryAfterSeconds: probeRateLimitedRetryAfter,
		}
	}
	if g.inFlight >= probeMaxActiveJobs+probeMaxQueuedJobs {
		return &nativeapi.APIError{
			Status:            503,
			Code:              "temporarily_unavailable",
			Message:           "probe queue is full",
			RetryAfterSeconds: 1,
		}
	}
	g.windowCount++
	g.inFlight++
	return nil
}

// run waits for a concurrency slot, runs fn, then frees the queue slot.
func (g *probeGate) run(fn func()) {
	if g == nil {
		fn()
		return
	}
	g.slots <- struct{}{}
	defer func() { <-g.slots }()
	defer func() {
		g.mu.Lock()
		g.inFlight--
		g.mu.Unlock()
	}()
	fn()
}

// StartProbe queues one bounded probe operation.
func (o *nativeAPIOperations) StartProbe(ctx context.Context, request nativeapi.ProbeRequest, idempotencyKey string) (nativeapi.OperationAccepted, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	if o == nil || o.store == nil {
		return nativeapi.OperationAccepted{}, nativeapi.NewAPIError(503, "temporarily_unavailable", "the operation store is unavailable")
	}
	// Reserve first: a probe refused by the gate or the rate limit must not
	// leave an operation record behind for the whole retention window.
	if err := o.probes.reserve(time.Now()); err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	accepted, replayed, err := o.store.Accept(nativeapi.OperationKindProbe, probeScope(request), idempotencyKey)
	if err != nil {
		o.probes.release()
		return nativeapi.OperationAccepted{}, err
	}
	if replayed {
		// The original request already queued this work.
		o.probes.release()
		return accepted, nil
	}
	go o.runProbe(accepted.OperationID, request)
	return accepted, nil
}

func (o *nativeAPIOperations) runProbe(operationID string, request nativeapi.ProbeRequest) {
	o.probes.run(func() {
		o.store.Start(operationID)
		o.events.publishOperationUpdated(operationID, "running")
		result, err := o.executeProbe(request)
		if err != nil {
			o.store.Fail(operationID, &nativeapi.SafeError{Code: "probe_failed", Message: err.Error()})
			o.events.publishOperationUpdated(operationID, "failed")
			return
		}
		o.store.Succeed(operationID, result)
		o.events.publishOperationUpdated(operationID, "succeeded")
	})
}

func (o *nativeAPIOperations) executeProbe(request nativeapi.ProbeRequest) (nativeapi.ProbeResult, error) {
	active := o.supervisor.activeSnapshot()
	if active == nil || active.controlPlane == nil {
		return nativeapi.ProbeResult{}, fmt.Errorf("no active runtime generation")
	}
	plane := active.controlPlane
	members, err := probeMembers(plane, request)
	if err != nil {
		return nativeapi.ProbeResult{}, err
	}
	result := nativeapi.ProbeResult{
		Target:           request.Target,
		SelectionChanged: nativeapi.TransportBooleanMap{},
		SelectionBefore:  nativeapi.TransportSelectionMap{},
		SelectionAfter:   nativeapi.TransportSelectionMap{},
		Results:          make([]nativeapi.ProbeResultItem, 0, len(members)*len(request.Transport)),
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeJobTimeout)
	defer cancel()
	soMark := plane.SoMarkFromDae()
	for _, member := range members {
		if ctx.Err() != nil {
			break
		}
		for _, transport := range request.Transport {
			if len(result.Results) >= probeMaxResultsPerJob || ctx.Err() != nil {
				break
			}
			result.Results = append(result.Results, runProbeMember(ctx, member, request, transport, soMark, plane.DirectDialer()))
		}
	}
	return result, nil
}

type probeMember struct {
	id     string
	dialer *dialer.Dialer
}

func probeMembers(plane *control.ControlPlane, request nativeapi.ProbeRequest) ([]probeMember, error) {
	nodeMap := make(map[string]*dialer.Dialer)
	for _, item := range plane.EgressDialers() {
		if property := item.Property(); property != nil {
			nodeMap[nodeIDOf(property)] = item
		}
	}
	if request.Target.Type == "node" {
		item, ok := nodeMap[request.Target.NodeID]
		if !ok {
			return nil, fmt.Errorf("node not found")
		}
		return []probeMember{{id: request.Target.NodeID, dialer: item}}, nil
	}

	groups := make(map[string]*dialer.Dialer)
	groupDialers := make(map[string][]*dialer.Dialer)
	for _, group := range plane.OutboundGroups() {
		if group == nil {
			continue
		}
		id := groupIDOf(group.Name)
		groupDialers[id] = group.Dialers
		for _, item := range group.Dialers {
			if property := item.Property(); property != nil {
				groups[nodeIDOf(property)] = item
			}
		}
	}
	if _, ok := groupDialers[request.Target.GroupID]; !ok {
		return nil, fmt.Errorf("group not found")
	}

	var selected []string
	if request.Members == nil || len(request.Members.Values) == 0 {
		selected = append(selected, request.Target.GroupID)
	} else {
		for _, value := range request.Members.Values {
			if value == "direct" || value == "leaves" {
				selected = append(selected, request.Target.GroupID)
				continue
			}
			selected = append(selected, value)
		}
	}

	seen := map[string]struct{}{}
	members := make([]probeMember, 0, len(selected))
	addDialers := func(groupID string) {
		for _, item := range groupDialers[groupID] {
			property := item.Property()
			if property == nil {
				continue
			}
			id := nodeIDOf(property)
			if _, duplicate := seen[id]; duplicate {
				continue
			}
			seen[id] = struct{}{}
			members = append(members, probeMember{id: id, dialer: item})
		}
	}
	for _, value := range selected {
		if _, isGroup := groupDialers[value]; isGroup {
			addDialers(value)
			continue
		}
		if item, ok := nodeMap[value]; ok {
			id := value
			if _, duplicate := seen[id]; duplicate {
				continue
			}
			seen[id] = struct{}{}
			members = append(members, probeMember{id: id, dialer: item})
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i].id < members[j].id })
	if len(members) > probeMaxMembersPerJob {
		return nil, nativeapi.NewAPIError(422, "invalid_request", "probe expands to more members than this engine supports")
	}
	return members, nil
}

func runProbeMember(parent context.Context, member probeMember, request nativeapi.ProbeRequest, transport string, soMark uint32, direct netproxy.Dialer) nativeapi.ProbeResultItem {
	purpose := "data"
	if request.Kind == "dns" {
		purpose = "dns"
	}
	item := nativeapi.ProbeResultItem{
		MemberID:      member.id,
		Kind:          request.Kind,
		Purpose:       purpose,
		Transport:     transport,
		IPVersion:     request.IPVersion,
		Warmth:        request.Warmth,
		State:         "unknown",
		HealthUpdated: false,
		ObservedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if item.IPVersion == "any" {
		item.IPVersion = "ipv4"
	}
	if member.dialer == nil {
		item.State = "unavailable"
		reason := "dialer is unavailable"
		item.Error = &reason
		return item
	}
	ctx, cancel := context.WithTimeout(parent, probeTimeout)
	defer cancel()

	// Deadlines alone do not bound a probe: the pinned HTTP/2 transport
	// implements SetDeadline as a no-op, and a peer that never answers would
	// then hold one of the few probe slots for good. Every connection a probe
	// opens is registered here and closed when the context ends.
	conns := &probeConnRegistry{}
	go func() {
		<-ctx.Done()
		conns.closeAll()
	}()

	var (
		err     error
		elapsed time.Duration
	)
	switch request.Kind {
	case "tcp_connect":
		// Report what the probe claims to test: whether the node's own server
		// accepts a TCP connection. Dialling 1.1.1.1 through the proxy measured
		// the far side's reachability instead, so a working node answered
		// unavailable whenever the exit could not reach that address.
		address := probeNodeAddress(member.dialer)
		if address == "" {
			// A node without a server address (the builtin direct outbound) has
			// no server to connect to, so fall back to a dial through the node.
			address = probeDialAddress("tcp", item.IPVersion)
			elapsed, err = dialAndClose(ctx, conns, member.dialer, soMark, "tcp", address)
		} else {
			elapsed, err = dialAndClose(ctx, conns, direct, soMark, "tcp", address)
		}
	case "http":
		elapsed, err = probeHTTP(ctx, conns, member.dialer, soMark, item.IPVersion)
	case "dns":
		elapsed, err = probeDNS(ctx, conns, member.dialer, soMark, item.IPVersion, transport)
	default:
		item.State = "unavailable"
		reason := fmt.Sprintf("probe kind %q is not supported", request.Kind)
		item.Error = &reason
		return item
	}
	if err != nil {
		item.State = "unavailable"
		reason := sanitizeLogMessage(err.Error())
		item.Error = &reason
		return item
	}
	latency := float64(elapsed.Microseconds()) / 1000
	item.State = "healthy"
	item.LatencyMs = &latency
	return item
}

// probeNodeAddress returns the node's own server address, which is what a
// tcp_connect probe has to reach. It is empty for outbounds without a server.
func probeNodeAddress(d *dialer.Dialer) string {
	if d == nil {
		return ""
	}
	property := d.Property()
	if property == nil {
		return ""
	}
	host, port, err := net.SplitHostPort(property.Address)
	if err != nil || host == "" || port == "" {
		return ""
	}
	return property.Address
}

// probeDialAddress is the well-known endpoint a dial probe reaches through the
// node. It answers on 443, which is what an http probe talks to.
func probeDialAddress(network, ipVersion string) string {
	if ipVersion == "ipv6" {
		if network == "udp" {
			return "[2606:4700:4700::1111]:53"
		}
		return "[2606:4700:4700::1111]:443"
	}
	if network == "udp" {
		return "1.1.1.1:53"
	}
	return "1.1.1.1:443"
}

// probeDNSAddress is the resolver a DNS probe sends its query to. A DNS probe
// speaks DNS on both transports; the port does not follow the transport, so
// reusing probeDialAddress sent length-prefixed DNS frames to port 443.
func probeDNSAddress(ipVersion string) string {
	if ipVersion == "ipv6" {
		return "[2606:4700:4700::1111]:53"
	}
	return "1.1.1.1:53"
}

// probeConnRegistry tracks the connections one probe opened, so the context
// watcher can interrupt a read that ignores deadlines.
type probeConnRegistry struct {
	mu    sync.Mutex
	conns []io.Closer
}

func (r *probeConnRegistry) add(closer io.Closer) {
	if r == nil || closer == nil {
		return
	}
	r.mu.Lock()
	r.conns = append(r.conns, closer)
	r.mu.Unlock()
}

func (r *probeConnRegistry) closeAll() {
	if r == nil {
		return
	}
	r.mu.Lock()
	conns := r.conns
	r.conns = nil
	r.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func dialAndClose(ctx context.Context, conns *probeConnRegistry, d netproxy.Dialer, soMark uint32, network, address string) (time.Duration, error) {
	if d == nil {
		return 0, fmt.Errorf("dialer is unavailable")
	}
	started := time.Now()
	conn, err := d.DialContext(ctx, common.MagicNetwork(network, soMark, false), address)
	elapsed := time.Since(started)
	if err != nil {
		return 0, err
	}
	if conn != nil {
		_ = conn.Close()
	}
	return elapsed, nil
}

// probeHTTP sends a real request through the node and requires a real response.
// A bare TCP dial never proved the node forwards traffic.
func probeHTTP(ctx context.Context, conns *probeConnRegistry, d *dialer.Dialer, soMark uint32, ipVersion string) (time.Duration, error) {
	host := "1.1.1.1"
	if ipVersion == "ipv6" {
		host = "[2606:4700:4700::1111]"
	}
	target := "http://" + host + "/"
	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := d.DialContext(ctx, common.MagicNetwork(network, soMark, false), address)
		if err != nil {
			return nil, err
		}
		wrapped := &netproxy.FakeNetConn{Conn: conn}
		conns.add(wrapped)
		return wrapped, nil
	}
	client := &http.Client{
		Transport: &http.Transport{DialContext: dialContext, DisableKeepAlives: true},
		Timeout:   probeTimeout,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "dae-probe/1.0")
	started := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(started)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("http probe answered %d", resp.StatusCode)
	}
	return elapsed, nil
}

// probeDNS sends a real DNS query through the node and requires an answer to
// that query, not merely any DNS-shaped packet.
func probeDNS(ctx context.Context, conns *probeConnRegistry, d *dialer.Dialer, soMark uint32, ipVersion, transport string) (time.Duration, error) {
	network := "udp"
	if transport == "tcp" {
		network = "tcp"
	}
	address := probeDNSAddress(ipVersion)
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return 0, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return 0, err
	}
	query, err := builder.Finish()
	if err != nil {
		return 0, err
	}
	started := time.Now()
	conn, err := d.DialContext(ctx, common.MagicNetwork(network, soMark, false), address)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	conns.add(conn)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if network == "tcp" {
		if err := writeDNSOverTCP(conn, query); err != nil {
			return 0, err
		}
		reply, err := readDNSOverTCP(conn)
		if err != nil {
			return 0, err
		}
		return parseDNSReply(reply, query, time.Since(started))
	}
	if _, err := conn.Write(query); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}
	return parseDNSReply(buf[:n], query, time.Since(started))
}

func writeDNSOverTCP(conn io.Writer, query []byte) error {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(query)))
	if _, err := conn.Write(append(length, query...)); err != nil {
		return err
	}
	return nil
}

func readDNSOverTCP(conn io.Reader) ([]byte, error) {
	length := make([]byte, 2)
	if _, err := io.ReadFull(conn, length); err != nil {
		return nil, err
	}
	reply := make([]byte, binary.BigEndian.Uint16(length))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// parseDNSReply requires the answer to echo the transaction ID and the question
// of the request. A header-only reply, or one carrying another question, came
// from a different exchange and must not pass for a healthy DNS probe.
func parseDNSReply(reply []byte, query []byte, elapsed time.Duration) (time.Duration, error) {
	var queryParser dnsmessage.Parser
	queryHeader, queryErr := queryParser.Start(query)
	if queryErr != nil {
		return 0, fmt.Errorf("dns probe query is malformed")
	}
	queryQuestion, queryErr := queryParser.Question()
	if queryErr != nil {
		return 0, fmt.Errorf("dns probe query carries no question")
	}

	var parser dnsmessage.Parser
	header, err := parser.Start(reply)
	if err != nil {
		return 0, fmt.Errorf("dns probe reply is malformed")
	}
	if !header.Response {
		return 0, fmt.Errorf("dns probe reply is not a response")
	}
	if header.ID != queryHeader.ID {
		return 0, fmt.Errorf("dns probe reply carries transaction ID %d, want %d", header.ID, queryHeader.ID)
	}
	replyQuestion, err := parser.Question()
	if err != nil {
		return 0, fmt.Errorf("dns probe reply carries no question")
	}
	if replyQuestion != queryQuestion {
		return 0, fmt.Errorf("dns probe reply answers %s/%d, want %s/%d",
			replyQuestion.Name.String(), replyQuestion.Type, queryQuestion.Name.String(), queryQuestion.Type)
	}
	return elapsed, nil
}

var _ nativeapi.ProbeProvider = (*nativeAPIOperations)(nil)

// probeScope identifies one probe request for the idempotency check, so a key
// reused for a different target or transport is a conflict instead of a replay.
func probeScope(request nativeapi.ProbeRequest) string {
	target := request.Target.Type + ":" + request.Target.NodeID + ":" + request.Target.GroupID
	if request.Members != nil {
		target += fmt.Sprint(request.Members.Values)
	}
	return request.Kind + "\x00" + target + "\x00" + strings.Join(request.Transport, ",") + "\x00" + request.IPVersion + "\x00" + request.Warmth
}
