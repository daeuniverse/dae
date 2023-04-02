/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"fmt"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"hash/fnv"
	"math/rand"
	"reflect"
	"testing"
)

var TestSample = []string{
	"9game.cn",
	"aliapp.org",
	"alibaba-inc.com",
	"alibaba.com",
	"alibabacapital.com",
	"alibabacorp.com",
	"alibabadoctor.com",
	"alibabafuturehotel.com",
	"alibabagroup.com",
	"alibabaplanet.com",
	"alibabaued.com",
	"alibabausercontent.com",
	"alifanyi.com",
	"alihealth.com.cn",
	"alihealth.hk",
	"aliimg.com",
	"51y5.net",
	"a.adtng.com",
	"aaxads.com",
	"addthisedge.com",
	"adtrue.com",
	"ad-srv.net",
	"ad.api.moji.com",
	"ad.wang502.com",
	"adbutter.net",
	"ads.trafficjunky.net",
	"adtechus.com",
	"adxprtz.com",
	"cdn.advertserve.com",
	"cdn.banclip.com",
	"cfts1tifqr.com",
	"contentabc.com",
	"cretgate.com",
	"ero-advertising.com",
	"eroadvertising.com",
	"exoclick.com",
	"exosrv.com",
	"go2.global",
	"img-bss.csdn.net",
	"imglnkc.com",
	"imglnkd.com",
	"innovid.com",
	"ja2.gamersky.com",
	"jl3.yjaxa.top",
	"juicyads.com",
	"kepler-37b.com",
	"lqc006.com",
	"moat.com",
	"moatads.com",
	"realsrv.com",
	"s4yxaqyq95.com",
	"shhs-ydd8x2.yjrmss.cn",
	"static.javhd.com",
	"tm-banners.gamingadult.com",
	"trafficfactory.biz",
	"tsyndicate.com",
	"abchina.com",
	"bankcomm.com",
	"bankofbeijing.com.cn",
	"bosc.cn",
	"bsb.com.cn",
	"ccb.com",
	"cgbchina.com.cn",
	"cib.com.cn",
	"citibank.com.cn",
	"cmbc.com.cn",
	"hsbc.com.cn",
	"hxb.com.cn",
	"njcb.com.cn",
	"psbc.com",
	"spdb.com.cn",
	"whccb.com",
}

type RoutingMatcherBuilder struct {
	outboundName2Id    map[string]uint8
	simulatedDomainSet []routing.DomainSet
	Fallback           string

	err error
}

func (b *RoutingMatcherBuilder) OutboundToId(outbound string) uint8 {
	h := fnv.New64()
	h.Write([]byte(outbound))
	return uint8(h.Sum64() & 0xFF)
}

func (b *RoutingMatcherBuilder) AddDomain(f *config_parser.Function, key string, values []string, outbound *routing.Outbound) {
	if b.err != nil {
		return
	}
	switch consts.RoutingDomainKey(key) {
	case consts.RoutingDomainKey_Regex,
		consts.RoutingDomainKey_Full,
		consts.RoutingDomainKey_Keyword,
		consts.RoutingDomainKey_Suffix:
	default:
		b.err = fmt.Errorf("addDomain: unsupported key: %v", key)
		return
	}
	b.simulatedDomainSet = append(b.simulatedDomainSet, routing.DomainSet{
		Key:       consts.RoutingDomainKey(key),
		RuleIndex: len(b.simulatedDomainSet),
		Domains:   values,
	})
}

func getDomain() (simulatedDomainSet []routing.DomainSet, err error) {
	var rules []*config_parser.RoutingRule
	sections, err := config_parser.Parse(`
routing {
	domain(geosite:bing)->us
    domain(full:dns.google.com) -> direct
	domain(geosite:category-ads-all) -> block
    domain(geosite:cn) -> direct
}`)
	if err != nil {
		return nil, err
	}
	var r config.Routing
	if err = config.SectionParser(reflect.ValueOf(&r), sections[0]); err != nil {
		return nil, err
	}
	if rules, err = routing.ApplyRulesOptimizers(r.Rules,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{Logger: logrus.StandardLogger()},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, fmt.Errorf("ApplyRulesOptimizers error:\n%w", err)
	}
	builder := RoutingMatcherBuilder{}
	rb := routing.NewRulesBuilder(logrus.StandardLogger())
	rb.RegisterFunctionParser("domain", func(log *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *routing.Outbound) (err error) {
		builder.AddDomain(f, key, paramValueGroup, overrideOutbound)
		return nil
	})
	if err = rb.Apply(rules); err != nil {
		return nil, fmt.Errorf("Apply: %w", err)
	}
	return builder.simulatedDomainSet, nil
}

func BenchmarkBruteforce(b *testing.B) {
	b.StopTimer()
	logrus.SetLevel(logrus.WarnLevel)
	simulatedDomainSet, err := getDomain()
	if err != nil {
		b.Fatal(err)
	}
	bf := NewBruteforce(consts.MaxMatchSetLen)
	for _, domains := range simulatedDomainSet {
		bf.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = bf.Build(); err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	runBenchmark(b, bf)
}

func BenchmarkGoRegexpNfa(b *testing.B) {
	b.StopTimer()
	logrus.SetLevel(logrus.WarnLevel)
	simulatedDomainSet, err := getDomain()
	if err != nil {
		b.Fatal(err)
	}
	nfa := NewGoRegexpNfa(consts.MaxMatchSetLen)
	for _, domains := range simulatedDomainSet {
		nfa.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = nfa.Build(); err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	runBenchmark(b, nfa)
}

func BenchmarkAhocorasickSlimtrie(b *testing.B) {
	b.StopTimer()
	logrus.SetLevel(logrus.WarnLevel)
	simulatedDomainSet, err := getDomain()
	if err != nil {
		b.Fatal(err)
	}
	ahocorasick := NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	for _, domains := range simulatedDomainSet {
		ahocorasick.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = ahocorasick.Build(); err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	runBenchmark(b, ahocorasick)
}

func runBenchmark(b *testing.B, matcher routing.DomainMatcher) {
	rand.Seed(100)
	for i := 0; i < b.N; i++ {
		sample := TestSample[rand.Intn(len(TestSample))]
		choice := rand.Intn(10)
		switch {
		case choice < 4:
			addN := rand.Intn(5)
			buf := make([]byte, addN)
			for i := range buf {
				buf[i] = 'a' + byte(rand.Intn('z'-'a'))
			}
			sample = string(buf) + "." + sample
		case choice >= 4 && choice < 6:
			k := rand.Intn(len(sample))
			sample = sample[k:]
		default:
		}
		matcher.MatchDomainBitmap(sample)
	}
}
