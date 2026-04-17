/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/netutils"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/dlclark/regexp2"
	"github.com/sirupsen/logrus"
)

const (
	functionSub     = "sub"
	functionNode    = "node"
	functionSubNode = "subnode"
)

type NodeMeta struct {
	SubscriptionTag string
	Name            string
	Link            string
	AddressHost     string
}

type subscriptionMeta struct {
	Tag  string
	Link string
}

type Router struct {
	log             *logrus.Logger
	upstreams       map[string]*componentdns.UpstreamResolver
	upstreamByIndex []*componentdns.UpstreamResolver
	requestMatcher  *componentdns.RequestMatcher
	subMatcher      *compiledMatcher[subscriptionMeta]
	nodeMatcher     *compiledMatcher[NodeMeta]
	subNodeMatcher  *compiledMatcher[NodeMeta]
	bootstrapDns    []netip.AddrPort
	soMark          uint32
	mptcp           bool
	lookupMu        sync.Mutex
	lookupCalls     map[string]*lookupCall
}

type lookupCall struct {
	waiters int
	done    chan struct{}
	res     []net.IPAddr
	err     error
	cancel  context.CancelFunc
}

type NewOption struct {
	LocationFinder *assets.LocationFinder
}

type compiledMatcher[T any] struct {
	rules []compiledRule[T]
}

type compiledRule[T any] struct {
	predicates []func(T) bool
	upstream   string
}

func (m *compiledMatcher[T]) Match(input T) (string, bool) {
	if m == nil {
		return "", false
	}
	for _, rule := range m.rules {
		matched := true
		for _, predicate := range rule.predicates {
			if !predicate(input) {
				matched = false
				break
			}
		}
		if matched {
			return rule.upstream, true
		}
	}
	return "", false
}

func New(log *logrus.Logger, global *config.Global, dnsCfg *config.Dns) (*Router, error) {
	return NewWithOption(log, global, dnsCfg, nil)
}

func NewWithOption(log *logrus.Logger, global *config.Global, dnsCfg *config.Dns, opt *NewOption) (*Router, error) {
	if dnsCfg == nil {
		return nil, nil
	}

	dnsRules, subRules, nodeRules, subNodeRules, err := componentdns.SplitRequestRules(dnsCfg.Routing.Request.Rules)
	if err != nil {
		return nil, err
	}
	locationFinder := assets.NewLocationFinder(nil)
	if opt != nil && opt.LocationFinder != nil {
		locationFinder = opt.LocationFinder
	}
	dnsRules, err = routing.ApplyRulesOptimizers(dnsRules,
		&routing.DatReaderOptimizer{Logger: log, LocationFinder: locationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	)
	if err != nil {
		return nil, err
	}
	if len(dnsRules) == 0 && len(subRules) == 0 && len(nodeRules) == 0 && len(subNodeRules) == 0 {
		return nil, nil
	}

	router := &Router{
		log:         log,
		upstreams:   make(map[string]*componentdns.UpstreamResolver),
		soMark:      common.EffectiveSoMarkFromDae(global.SoMarkFromDae),
		mptcp:       global.Mptcp,
		lookupCalls: make(map[string]*lookupCall),
	}
	router.bootstrapDns, err = config.BootstrapResolvers(global)
	if err != nil {
		return nil, err
	}
	if err = router.initUpstreams(dnsCfg.Upstream); err != nil {
		return nil, err
	}
	upstreamName2Id := make(map[string]uint8, len(router.upstreamByIndex))
	for i, upstreamRaw := range dnsCfg.Upstream {
		tag, _ := common.GetTagFromLinkLikePlaintext(string(upstreamRaw))
		if tag == "" {
			continue
		}
		upstreamName2Id[tag] = uint8(i)
	}
	requestMatcherBuilder, err := componentdns.NewRequestMatcherBuilder(log, dnsRules, upstreamName2Id, dnsCfg.Routing.Request.Fallback)
	if err != nil {
		return nil, err
	}
	router.requestMatcher, err = requestMatcherBuilder.Build()
	if err != nil {
		return nil, err
	}

	router.subMatcher, err = router.compileSubscriptionMatcher(subRules)
	if err != nil {
		return nil, err
	}
	router.nodeMatcher, err = router.compileNodeMatcher(nodeRules)
	if err != nil {
		return nil, err
	}
	router.subNodeMatcher, err = router.compileSubNodeMatcher(subNodeRules)
	if err != nil {
		return nil, err
	}
	return router, nil
}

func (r *Router) initUpstreams(rawUpstreams []config.KeyableString) error {
	resolveIp46 := r.resolveBootstrap
	if len(r.bootstrapDns) == 0 {
		resolveIp46 = nil
	}
	for _, upstreamRaw := range rawUpstreams {
		tag, link := common.GetTagFromLinkLikePlaintext(string(upstreamRaw))
		if tag == "" {
			continue
		}
		u, err := url.Parse(link)
		if err != nil {
			return fmt.Errorf("bad dns upstream %q: %w", upstreamRaw, err)
		}
		r.upstreams[tag] = &componentdns.UpstreamResolver{
			Raw:         u,
			Network:     common.MagicNetwork("udp", r.soMark, r.mptcp),
			ResolveIp46: resolveIp46,
		}
		r.upstreamByIndex = append(r.upstreamByIndex, r.upstreams[tag])
	}
	return nil
}

func (r *Router) WrapSubscriptionDialer(base netproxy.Dialer, rawSubscription string) (netproxy.Dialer, error) {
	if r == nil {
		return base, nil
	}
	tag, link := common.GetTagFromLinkLikePlaintext(rawSubscription)
	upstream, ok := r.subMatcher.Match(subscriptionMeta{
		Tag:  tag,
		Link: link,
	})
	controlHost := subscriptionHost(link)
	if !ok && r.requestMatcher == nil && controlHost == "" {
		return base, nil
	}
	return &resolvingDialer{
		Dialer:              base,
		router:              r,
		upstreamName:        upstream,
		controlUpstreamName: upstream,
		controlHost:         controlHost,
	}, nil
}

func (r *Router) WrapNodeDialer(base netproxy.Dialer, meta NodeMeta) (netproxy.Dialer, error) {
	if r == nil {
		return base, nil
	}
	var (
		upstream string
		ok       bool
	)
	if meta.SubscriptionTag != "" {
		upstream, ok = r.subNodeMatcher.Match(meta)
	}
	if !ok {
		upstream, ok = r.nodeMatcher.Match(meta)
	}
	if !ok && r.requestMatcher == nil && meta.AddressHost == "" {
		return base, nil
	}
	return &resolvingDialer{
		Dialer:              base,
		router:              r,
		upstreamName:        upstream,
		controlUpstreamName: upstream,
		controlHost:         meta.AddressHost,
	}, nil
}

func (r *Router) MatchSubscriptionUpstream(rawSubscription string) (string, bool) {
	if r == nil {
		return "", false
	}
	tag, link := common.GetTagFromLinkLikePlaintext(rawSubscription)
	return r.subMatcher.Match(subscriptionMeta{
		Tag:  tag,
		Link: link,
	})
}

func (r *Router) MatchNodeUpstream(meta NodeMeta) (string, bool) {
	if r == nil {
		return "", false
	}
	if meta.SubscriptionTag != "" {
		if upstream, ok := r.subNodeMatcher.Match(meta); ok {
			return upstream, true
		}
	}
	return r.nodeMatcher.Match(meta)
}

func (r *Router) compileSubscriptionMatcher(rules []*config_parser.RoutingRule) (*compiledMatcher[subscriptionMeta], error) {
	return compileMatcher(r.upstreams, rules, functionSub, compileSubscriptionPredicate)
}

func (r *Router) compileNodeMatcher(rules []*config_parser.RoutingRule) (*compiledMatcher[NodeMeta], error) {
	return compileMatcher(r.upstreams, rules, functionNode, compileNodePredicate)
}

func (r *Router) compileSubNodeMatcher(rules []*config_parser.RoutingRule) (*compiledMatcher[NodeMeta], error) {
	return compileMatcher(r.upstreams, rules, functionSubNode, compileSubNodePredicate)
}

func compileMatcher[T any](
	upstreams map[string]*componentdns.UpstreamResolver,
	rules []*config_parser.RoutingRule,
	expectedFunc string,
	compilePredicate func(f *config_parser.Function) (func(T) bool, error),
) (*compiledMatcher[T], error) {
	if len(rules) == 0 {
		return nil, nil
	}
	matcher := &compiledMatcher[T]{}
	for _, rule := range rules {
		outbound, err := routing.ParseOutbound(&rule.Outbound)
		if err != nil {
			return nil, err
		}
		if outbound.Mark != 0 || outbound.Must {
			return nil, fmt.Errorf("%s rules only support plain dns upstream targets: %v", expectedFunc, rule.String(false, false, false))
		}
		if _, ok := upstreams[outbound.Name]; !ok {
			return nil, fmt.Errorf("dns upstream %q not found for %s rule: %v", outbound.Name, expectedFunc, rule.String(false, false, false))
		}
		compiled := compiledRule[T]{upstream: outbound.Name}
		for _, f := range rule.AndFunctions {
			if f.Name != expectedFunc {
				return nil, fmt.Errorf("unexpected function %q in %s rule: %v", f.Name, expectedFunc, rule.String(false, false, false))
			}
			predicate, err := compilePredicate(f)
			if err != nil {
				return nil, err
			}
			compiled.predicates = append(compiled.predicates, predicate)
		}
		matcher.rules = append(matcher.rules, compiled)
	}
	return matcher, nil
}

func compileSubscriptionPredicate(f *config_parser.Function) (func(subscriptionMeta) bool, error) {
	conditions := make([]func(subscriptionMeta) bool, 0, 1)
	if len(f.Params) == 0 {
		conditions = append(conditions, func(subscriptionMeta) bool { return true })
	}
	groups, keyOrder, err := groupParamValuesByKey(f.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to parse '%v': %w", f.String(false, false, false), err)
	}
	for _, key := range keyOrder {
		values := groups[key]
		condition, err := compileSubscriptionCondition(key, values)
		if err != nil {
			return nil, fmt.Errorf("failed to parse '%v': %w", f.String(false, false, false), err)
		}
		conditions = append(conditions, condition)
	}
	return wrapNotPredicate(conditions, f.Not), nil
}

func compileNodePredicate(f *config_parser.Function) (func(NodeMeta) bool, error) {
	conditions := make([]func(NodeMeta) bool, 0, 1)
	if len(f.Params) == 0 {
		conditions = append(conditions, func(NodeMeta) bool { return true })
	}
	groups, keyOrder, err := groupParamValuesByKey(f.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to parse '%v': %w", f.String(false, false, false), err)
	}
	for _, key := range keyOrder {
		values := groups[key]
		condition, err := compileNodeCondition(key, values)
		if err != nil {
			return nil, fmt.Errorf("failed to parse '%v': %w", f.String(false, false, false), err)
		}
		conditions = append(conditions, condition)
	}
	return wrapNotPredicate(conditions, f.Not), nil
}

func compileSubNodePredicate(f *config_parser.Function) (func(NodeMeta) bool, error) {
	conditions := make([]func(NodeMeta) bool, 0, 1)
	if len(f.Params) == 0 {
		conditions = append(conditions, func(meta NodeMeta) bool { return meta.SubscriptionTag != "" })
	}
	groups, keyOrder, err := groupParamValuesByKey(f.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to parse '%v': %w", f.String(false, false, false), err)
	}
	for _, key := range keyOrder {
		values := groups[key]
		condition, err := compileSubNodeCondition(key, values)
		if err != nil {
			return nil, fmt.Errorf("failed to parse '%v': %w", f.String(false, false, false), err)
		}
		conditions = append(conditions, condition)
	}
	base := wrapNotPredicate(conditions, f.Not)
	return func(meta NodeMeta) bool {
		if meta.SubscriptionTag == "" {
			return false
		}
		return base(meta)
	}, nil
}

func wrapNotPredicate[T any](conditions []func(T) bool, not bool) func(T) bool {
	return func(input T) bool {
		matched := false
		for _, condition := range conditions {
			if condition(input) {
				matched = true
				break
			}
		}
		if not {
			return !matched
		}
		return matched
	}
}

func compileSubscriptionCondition(key string, values []string) (func(subscriptionMeta) bool, error) {
	switch key {
	case "", "tag":
		return func(meta subscriptionMeta) bool {
			for _, value := range values {
				if meta.Tag == value {
					return true
				}
			}
			return false
		}, nil
	case "tag_regex", "regex":
		regexps, err := compileRegexps(values)
		if err != nil {
			return nil, err
		}
		return func(meta subscriptionMeta) bool {
			return matchAnyRegexp(regexps, meta.Tag)
		}, nil
	case "link_keyword":
		return func(meta subscriptionMeta) bool {
			for _, value := range values {
				if strings.Contains(meta.Link, value) {
					return true
				}
			}
			return false
		}, nil
	case "link_regex":
		regexps, err := compileRegexps(values)
		if err != nil {
			return nil, err
		}
		return func(meta subscriptionMeta) bool {
			return matchAnyRegexp(regexps, meta.Link)
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key %q", key)
	}
}

func compileNodeCondition(key string, values []string) (func(NodeMeta) bool, error) {
	switch key {
	case "", "name":
		return func(meta NodeMeta) bool {
			for _, value := range values {
				if meta.Name == value {
					return true
				}
			}
			return false
		}, nil
	case "name_keyword":
		return func(meta NodeMeta) bool {
			for _, value := range values {
				if strings.Contains(meta.Name, value) {
					return true
				}
			}
			return false
		}, nil
	case "name_regex":
		regexps, err := compileRegexps(values)
		if err != nil {
			return nil, err
		}
		return func(meta NodeMeta) bool {
			return matchAnyRegexp(regexps, meta.Name)
		}, nil
	case "link_keyword":
		return func(meta NodeMeta) bool {
			for _, value := range values {
				if strings.Contains(meta.Link, value) {
					return true
				}
			}
			return false
		}, nil
	case "link_regex":
		regexps, err := compileRegexps(values)
		if err != nil {
			return nil, err
		}
		return func(meta NodeMeta) bool {
			return matchAnyRegexp(regexps, meta.Link)
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key %q", key)
	}
}

func compileSubNodeCondition(key string, values []string) (func(NodeMeta) bool, error) {
	switch key {
	case "", "subtag":
		return func(meta NodeMeta) bool {
			for _, value := range values {
				if meta.SubscriptionTag == value {
					return true
				}
			}
			return false
		}, nil
	case "subtag_regex", "regex":
		regexps, err := compileRegexps(values)
		if err != nil {
			return nil, err
		}
		return func(meta NodeMeta) bool {
			return matchAnyRegexp(regexps, meta.SubscriptionTag)
		}, nil
	case "name", "name_keyword", "name_regex", "link_keyword", "link_regex":
		return compileNodeCondition(key, values)
	default:
		return nil, fmt.Errorf("unsupported key %q", key)
	}
}

func compileRegexps(values []string) ([]*regexp2.Regexp, error) {
	regexps := make([]*regexp2.Regexp, 0, len(values))
	for _, value := range values {
		re, err := regexp2.Compile(value, 0)
		if err != nil {
			return nil, err
		}
		regexps = append(regexps, re)
	}
	return regexps, nil
}

func matchAnyRegexp(regexps []*regexp2.Regexp, value string) bool {
	for _, re := range regexps {
		matched, _ := re.MatchString(value)
		if matched {
			return true
		}
	}
	return false
}

func groupParamValuesByKey(params []*config_parser.Param) (map[string][]string, []string, error) {
	grouped := make(map[string][]string)
	var keyOrder []string
	for _, param := range params {
		if len(param.AndFunctions) > 0 {
			return nil, nil, fmt.Errorf("nested functions are not supported in internal dae DNS selectors")
		}
		if _, ok := grouped[param.Key]; !ok {
			keyOrder = append(keyOrder, param.Key)
		}
		grouped[param.Key] = append(grouped[param.Key], param.Val)
	}
	return grouped, keyOrder, nil
}

func (r *Router) resolveBootstrap(ctx context.Context, host string, network string) (*netutils.Ip46, error, error) {
	if len(r.bootstrapDns) == 0 {
		err := fmt.Errorf("bootstrap resolver is not configured")
		return &netutils.Ip46{}, err, err
	}
	var firstErr4 error
	var firstErr6 error
	var lastNoRecord *netutils.Ip46
	var lastNoRecordErr4 error
	var lastNoRecordErr6 error
	for _, resolver := range r.bootstrapDns {
		ip46, err4, err6 := netutils.ResolveIp46(ctx, direct.SymmetricDirect, resolver, host, network, false)
		if ip46 == nil {
			ip46 = &netutils.Ip46{}
		}
		if ip46.Ip4.IsValid() || ip46.Ip6.IsValid() {
			return ip46, err4, err6
		}
		if err4 == nil || err6 == nil {
			lastNoRecord = ip46
			lastNoRecordErr4 = err4
			lastNoRecordErr6 = err6
			continue
		}
		if firstErr4 == nil {
			firstErr4 = err4
		}
		if firstErr6 == nil {
			firstErr6 = err6
		}
	}
	if lastNoRecord != nil {
		return lastNoRecord, lastNoRecordErr4, lastNoRecordErr6
	}
	if firstErr4 == nil {
		firstErr4 = fmt.Errorf("bootstrap resolver failed")
	}
	if firstErr6 == nil {
		firstErr6 = firstErr4
	}
	return &netutils.Ip46{}, firstErr4, firstErr6
}

func (r *Router) lookupBootstrapIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []net.IPAddr{{IP: net.IP(addr.AsSlice())}}, nil
	}
	dnsNetwork := common.MagicNetworkWithIPVersion("udp", r.soMark, r.mptcp, requestedIPVersion(network))
	ip46, err4, err6 := r.resolveBootstrap(ctx, host, dnsNetwork)
	addrs := make([]net.IPAddr, 0, 2)
	switch requestedIPVersion(network) {
	case "4":
		if ip46 != nil && ip46.Ip4.IsValid() {
			addrs = append(addrs, net.IPAddr{IP: net.IP(ip46.Ip4.AsSlice())})
		}
	case "6":
		if ip46 != nil && ip46.Ip6.IsValid() {
			addrs = append(addrs, net.IPAddr{IP: net.IP(ip46.Ip6.AsSlice())})
		}
	default:
		if ip46 != nil && ip46.Ip4.IsValid() {
			addrs = append(addrs, net.IPAddr{IP: net.IP(ip46.Ip4.AsSlice())})
		}
		if ip46 != nil && ip46.Ip6.IsValid() {
			addrs = append(addrs, net.IPAddr{IP: net.IP(ip46.Ip6.AsSlice())})
		}
	}
	if len(addrs) != 0 {
		return addrs, nil
	}
	if err4 != nil {
		return nil, err4
	}
	if err6 != nil {
		return nil, err6
	}
	return nil, fmt.Errorf("bootstrap resolver returned no usable address for %q", host)
}

func subscriptionHost(link string) string {
	if link == "" {
		return ""
	}
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func sameDNSHost(a, b string) bool {
	a = strings.TrimSuffix(a, ".")
	b = strings.TrimSuffix(b, ".")
	if a == "" || b == "" {
		return false
	}
	return strings.EqualFold(a, b)
}

type resolvingDialer struct {
	netproxy.Dialer
	router              *Router
	upstreamName        string
	controlUpstreamName string
	controlHost         string
}

func (d *resolvingDialer) lookupBaseIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	if resolver, ok := d.Dialer.(interface {
		LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
	}); ok {
		return resolver.LookupIPAddr(ctx, network, host)
	}
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

func (d *resolvingDialer) lookupControlIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	if d.controlUpstreamName == "" {
		return d.router.lookupBootstrapIPAddr(ctx, network, host)
	}
	ips, err := d.router.LookupIPAddr(ctx, d.controlUpstreamName, network, host)
	if errors.Is(err, errPassthroughToBaseResolver) {
		return d.router.lookupBootstrapIPAddr(ctx, network, host)
	}
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return d.router.lookupBootstrapIPAddr(ctx, network, host)
	}
	return ips, nil
}

func (d *resolvingDialer) lookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	if d.controlHost != "" && sameDNSHost(host, d.controlHost) {
		return d.lookupControlIPAddr(ctx, network, host)
	}
	ips, err := d.router.LookupIPAddr(ctx, d.upstreamName, network, host)
	if errors.Is(err, errPassthroughToBaseResolver) {
		return d.lookupBaseIPAddr(ctx, network, host)
	}
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 && d.upstreamName == "" {
		return d.lookupBaseIPAddr(ctx, network, host)
	}
	return ips, nil
}

func (d *resolvingDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return d.Dialer.DialContext(ctx, network, addr)
	}
	if _, err = netip.ParseAddr(host); err == nil {
		return d.Dialer.DialContext(ctx, network, addr)
	}
	ips, err := d.lookupIPAddr(ctx, network, host)
	if err != nil {
		return nil, err
	}
	var firstErr error
	for _, ip := range ips {
		conn, dialErr := d.Dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = dialErr
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("no address returned for %q", host)
	}
	return nil, firstErr
}

func (d *resolvingDialer) LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	return d.lookupIPAddr(ctx, network, host)
}
