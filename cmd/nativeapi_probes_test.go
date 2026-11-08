/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/dns/dnsmessage"
)

func apiErrorOf(t *testing.T, err error) *nativeapi.APIError {
	t.Helper()
	var apiErr *nativeapi.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *nativeapi.APIError", err)
	}
	return apiErr
}

// TestAcquireProbeTargetBoundsConcurrencyPerNode pins the advertised
// max_concurrent_per_target: a single job already runs several rows at once, so
// the limit must be enforced process-wide per node rather than per job.
func TestAcquireProbeTargetBoundsConcurrencyPerNode(t *testing.T) {
	o := &nativeAPIOperations{}
	ctx := context.Background()
	for i := 0; i < probeMaxActiveJobs; i++ {
		release, err := o.acquireProbeTarget(ctx, "n_shared")
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		defer release()
	}
	blocked, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := o.acquireProbeTarget(blocked, "n_shared"); err == nil {
		t.Fatal("a node must not exceed max_concurrent_per_target")
	}
	// A different node has its own slots.
	release, err := o.acquireProbeTarget(ctx, "n_other")
	if err != nil {
		t.Fatalf("acquire on another node: %v", err)
	}
	release()
}

func TestProbeGateBoundsQueue(t *testing.T) {
	gate := newProbeGate()
	now := time.Now()
	for i := 0; i < probeMaxActiveJobs+probeMaxQueuedJobs; i++ {
		if err := gate.reserve(now); err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
	}
	apiErr := apiErrorOf(t, gate.reserve(now))
	if apiErr.Status != 503 || apiErr.RetryAfterSeconds != 1 {
		t.Fatalf("queue full error = %+v, want 503 with Retry-After 1", apiErr)
	}
}

func TestProbeGateRateLimitAndWindowReset(t *testing.T) {
	gate := newProbeGate()
	now := time.Now()
	gate.windowStart = now
	gate.windowCount = probeGlobalRequestsPerMin

	apiErr := apiErrorOf(t, gate.reserve(now))
	if apiErr.Status != 429 || apiErr.RetryAfterSeconds != probeRateLimitedRetryAfter {
		t.Fatalf("rate limit error = %+v, want 429 with Retry-After %d", apiErr, probeRateLimitedRetryAfter)
	}

	if err := gate.reserve(now.Add(probeRateLimitWindow)); err != nil {
		t.Fatalf("reserve after window reset: %v", err)
	}
	gate.mu.Lock()
	inFlight := gate.inFlight
	gate.mu.Unlock()
	if inFlight != 1 {
		t.Fatalf("inFlight = %d, want 1", inFlight)
	}
}

func TestProbeGateRunsAtMostActiveJobsConcurrently(t *testing.T) {
	gate := newProbeGate()
	release := make(chan struct{})
	running := make(chan struct{}, probeMaxActiveJobs)
	for i := 0; i < probeMaxActiveJobs; i++ {
		go gate.run(func() {
			running <- struct{}{}
			<-release
		})
	}
	for i := 0; i < probeMaxActiveJobs; i++ {
		select {
		case <-running:
		case <-time.After(2 * time.Second):
			t.Fatal("probe slot did not start")
		}
	}

	started := make(chan struct{})
	go gate.run(func() { close(started) })
	select {
	case <-started:
		t.Fatal("probe beyond max_active_jobs started while all slots were busy")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("queued probe never started after slots were released")
	}
}

func TestProbeNodeAddressUsesTheNodeServer(t *testing.T) {
	// tcp_connect has to reach the node's own server, not a public address
	// through the proxy: a reachable node whose exit cannot reach 1.1.1.1 used
	// to answer unavailable.
	d, err := dialer.NewFromLinkContext(context.Background(), &dialer.GlobalOption{Log: logrus.New()}, dialer.InstanceOption{DisableCheck: true}, "socks5://192.0.2.10:1080", "")
	if err != nil {
		t.Fatalf("build dialer: %v", err)
	}
	defer func() { _ = d.Close() }()
	if got := probeNodeAddress(d); got != "192.0.2.10:1080" {
		t.Fatalf("probeNodeAddress = %q, want the node server 192.0.2.10:1080", got)
	}
	// An outbound with no server address falls back to the well-known endpoint.
	if got := probeNodeAddress(nil); got != "" {
		t.Fatalf("probeNodeAddress(nil) = %q, want empty", got)
	}
	if got := probeDialAddress("tcp", "ipv4"); got != "1.1.1.1:443" {
		t.Fatalf("probeDialAddress(tcp, ipv4) = %q", got)
	}
	if got := probeDialAddress("udp", "ipv6"); got != "[2606:4700:4700::1111]:53" {
		t.Fatalf("probeDialAddress(udp, ipv6) = %q", got)
	}
}

func TestProbeRejectsUnknownKind(t *testing.T) {
	item := runProbeMember(context.Background(), probeMember{id: "n", dialer: nil}, nativeapi.ProbeRequest{Kind: "icmp"}, "tcp", "ipv4", 0, nil, probeCheckTargets{})
	if item.State != "unavailable" {
		t.Fatalf("state = %q, want unavailable", item.State)
	}
	if item.Error == nil || *item.Error != "dialer is unavailable" {
		t.Fatalf("error = %v", item.Error)
	}
}

func TestProbeDNSSpeaksDNSOnBothTransports(t *testing.T) {
	// A DNS probe carries DNS regardless of transport, so it must reach port 53.
	// Reusing probeDialAddress sent length-prefixed DNS frames to 443.
	if got := probeDNSAddress("ipv4"); got != "1.1.1.1:53" {
		t.Fatalf("probeDNSAddress(ipv4) = %q, want 1.1.1.1:53", got)
	}
	if got := probeDNSAddress("ipv6"); got != "[2606:4700:4700::1111]:53" {
		t.Fatalf("probeDNSAddress(ipv6) = %q, want the IPv6 resolver on port 53", got)
	}
}

func TestParseDNSReplyRequiresMatchingIDAndQuestion(t *testing.T) {
	query := buildProbeDNSQuery(t, 7, "example.com.")
	matching := buildProbeDNSReply(t, query, 7, "example.com.")
	if _, err := parseDNSReply(matching, query, time.Millisecond); err != nil {
		t.Fatalf("parseDNSReply rejected a matching reply: %v", err)
	}

	// A header-only reply carries no answer and no question: it used to pass.
	headerOnly := buildProbeDNSReplyHeaderOnly(t, 7)
	if _, err := parseDNSReply(headerOnly, query, time.Millisecond); err == nil {
		t.Fatal("parseDNSReply accepted a header-only reply without a question")
	}
	// A reply for another transaction must not count as this probe's answer.
	wrongID := buildProbeDNSReply(t, query, 8, "example.com.")
	if _, err := parseDNSReply(wrongID, query, time.Millisecond); err == nil {
		t.Fatal("parseDNSReply accepted a reply with a different transaction ID")
	}
	// A reply for another question must not either.
	wrongQuestion := buildProbeDNSReply(t, query, 7, "other.example.")
	if _, err := parseDNSReply(wrongQuestion, query, time.Millisecond); err == nil {
		t.Fatal("parseDNSReply accepted a reply answering another question")
	}
}

func buildProbeDNSQuery(t *testing.T, id uint16, name string) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatalf("start questions: %v", err)
	}
	if err := builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatalf("question: %v", err)
	}
	msg, err := builder.Finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	return msg
}

func buildProbeDNSReply(t *testing.T, query []byte, id uint16, name string) []byte {
	t.Helper()
	var parser dnsmessage.Parser
	if _, err := parser.Start(query); err != nil {
		t.Fatalf("parse query: %v", err)
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, RecursionAvailable: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatalf("start questions: %v", err)
	}
	if err := builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatalf("question: %v", err)
	}
	msg, err := builder.Finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	return msg
}

func buildProbeDNSReplyHeaderOnly(t *testing.T, id uint16) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true})
	msg, err := builder.Finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	return msg
}

func TestParseDNSReplyRejectsDeclaredAnswerWithoutBytes(t *testing.T) {
	query := buildProbeDNSQuery(t, 7, "example.com.")
	reply := buildProbeDNSReply(t, query, 7, "example.com.")
	// ANCOUNT=1 with no answer bytes: the header claims a section the payload
	// does not contain. The old parser never read the section and reported it
	// healthy.
	binary.BigEndian.PutUint16(reply[6:8], 1)
	if _, err := parseDNSReply(reply, query, time.Millisecond); err == nil {
		t.Fatal("parseDNSReply accepted a declared but missing answer section")
	}
}

func TestProbeDeadlineRowIsUnknownNotUnavailable(t *testing.T) {
	item := probeUnavailableResult(probeMember{id: "n"}, nativeapi.ProbeRequest{Kind: "dns"}, "udp", "ipv4", "probe job deadline exceeded")
	if item.State != "unknown" {
		t.Fatalf("state = %q, want unknown for work that never ran", item.State)
	}
	if item.Warmth != "unknown" {
		t.Fatalf("warmth = %q, want unknown: a new logical stream does not prove a cold tunnel", item.Warmth)
	}
}

func TestProbeRowCancelledByJobDeadlineIsUnknown(t *testing.T) {
	// A row that started but was cut by the 30 s job deadline never produced
	// evidence about the node; the contract says unknown, not unavailable.
	option := &dialer.GlobalOption{Log: logrus.New(), CheckInterval: 15 * time.Second}
	d := newNamedDialer(option, &dialer.Property{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	item := runProbeMember(ctx, probeMember{id: "n", dialer: d}, nativeapi.ProbeRequest{Kind: "http"}, "tcp", "ipv4", 0, nil, probeCheckTargets{})
	if item.State != "unknown" {
		t.Fatalf("state = %q, want unknown for a row cut by the job deadline", item.State)
	}
	if item.Error == nil {
		t.Fatal("a deadline row must carry an error message")
	}
}

func TestProbeDoesNotClaimColdWhenTunnelWarmthIsUnknown(t *testing.T) {
	item := runProbeMember(context.Background(), probeMember{id: "n", dialer: nil}, nativeapi.ProbeRequest{Kind: "http"}, "tcp", "ipv4", 0, nil, probeCheckTargets{})
	if item.Warmth != "unknown" {
		t.Fatalf("warmth = %q, want unknown", item.Warmth)
	}
}

func TestProbeAddressForFamilyRejectsTheOtherFamily(t *testing.T) {
	if _, err := probeAddressForFamily(context.Background(), "1.1.1.1:53", "ipv6"); err == nil {
		t.Fatal("an IPv4 literal must not satisfy an ipv6 probe")
	}
	if _, err := probeAddressForFamily(context.Background(), "[2606:4700:4700::1111]:53", "ipv4"); err == nil {
		t.Fatal("an IPv6 literal must not satisfy an ipv4 probe")
	}
	got, err := probeAddressForFamily(context.Background(), "1.1.1.1:53", "ipv4")
	if err != nil || got != "1.1.1.1:53" {
		t.Fatalf("probeAddressForFamily = %q, %v", got, err)
	}
}

func TestProbeTargetsFallBackToGlobalChecks(t *testing.T) {
	active := &runtimeGeneration{conf: &config.Config{Global: config.Global{
		TcpCheckUrl:        []string{"http://check.example/generate_204"},
		TcpCheckHttpMethod: "HEAD",
		UdpCheckDns:        []string{"one.one.one.one:53"},
	}}}
	targets := probeTargetsFor(active, nil, nativeapi.ProbeRequest{
		Target: nativeapi.ProbeTarget{Type: "node", NodeID: "n_missing"},
	})
	if len(targets.http) == 0 || targets.http[0] != "http://check.example/generate_204" {
		t.Fatalf("http targets = %#v", targets.http)
	}
	if targets.httpMethod != "HEAD" {
		t.Fatalf("http method = %q, want HEAD from global config", targets.httpMethod)
	}
	if len(targets.dns) == 0 || targets.dns[0] != "one.one.one.one:53" {
		t.Fatalf("dns targets = %#v", targets.dns)
	}
}

func TestProbeCheckIPOverrideFollowsTheConfiguredFamily(t *testing.T) {
	// tcp_check_url / udp_check_dns keep the destination first and the literal
	// overrides after it; the health check dials those instead of resolving the
	// host, and a probe that ignored them went through the system resolver.
	raw := []string{"http://check.example/generate_204", "198.51.100.7", "2001:db8::7"}
	if got := probeCheckIPOverride(raw, "ipv4"); got != "198.51.100.7" {
		t.Fatalf("ipv4 override = %q", got)
	}
	if got := probeCheckIPOverride(raw, "ipv6"); got != "2001:db8::7" {
		t.Fatalf("ipv6 override = %q", got)
	}
	if got := probeCheckIPOverride(raw[:1], "ipv4"); got != "" {
		t.Fatalf("override without a literal = %q, want none", got)
	}
	// An unconfigured list is nil, and indexing it must stay safe.
	if got := probeCheckIPOverride(nil, "ipv4"); got != "" {
		t.Fatalf("override from an empty list = %q, want none", got)
	}
	if got := probeCheckIPOverride([]string{}, "ipv6"); got != "" {
		t.Fatalf("override from an empty list = %q, want none", got)
	}
}

// TestAcquireProbeTargetPrunesIdleNodes pins the memory behaviour of the slot
// table: a node id that is no longer probed must not stay in the map, or every
// node a long-running daemon ever probed would be retained forever.
func TestAcquireProbeTargetPrunesIdleNodes(t *testing.T) {
	o := &nativeAPIOperations{}
	ctx := context.Background()
	release, err := o.acquireProbeTarget(ctx, "n_transient")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if len(o.probeTargetSlots) != 1 {
		t.Fatalf("slots = %d, want 1 while a probe holds the node", len(o.probeTargetSlots))
	}
	release()
	if len(o.probeTargetSlots) != 0 {
		t.Fatalf("slots = %d, want the idle node to be pruned", len(o.probeTargetSlots))
	}

	// A cancelled wait releases its reference too, so an abandoned probe cannot
	// pin the entry.
	held, err := o.acquireProbeTarget(ctx, "n_busy")
	if err != nil {
		t.Fatalf("acquire busy: %v", err)
	}
	for i := 0; i < probeMaxActiveJobs-1; i++ {
		extra, err := o.acquireProbeTarget(ctx, "n_busy")
		if err != nil {
			t.Fatalf("acquire busy %d: %v", i, err)
		}
		defer extra()
	}
	cancelled, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := o.acquireProbeTarget(cancelled, "n_busy"); err == nil {
		t.Fatal("the slot set is full, the wait must time out")
	}
	held()
	if len(o.probeTargetSlots) != 1 {
		t.Fatalf("slots = %d, want the node kept by the remaining holders", len(o.probeTargetSlots))
	}
}
