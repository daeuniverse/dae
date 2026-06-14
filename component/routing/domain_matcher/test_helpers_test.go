/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"fmt"
	"reflect"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
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
	"_https._tcp.mirrors.ustc.edu.cn",
	"ipv4.master.test-ipv6.com",
}

type testRoutingMatcherBuilder struct {
	simulatedDomainSet []routing.DomainSet
	err                error
}

func (b *testRoutingMatcherBuilder) addDomain(_ *config_parser.Function, key string, values []string, outbound *routing.Outbound) {
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

func getDomain() ([]routing.DomainSet, error) {
	sections, err := config_parser.Parse(`
routing {
	domain(suffix: test-ipv6.com)->direct
	domain(geosite:bing)->us
	domain(_https._tcp.mirrors.ustc.edu.cn)->us
	domain(full:dns.google) -> direct
	domain(geosite:category-ads-all) -> block
	domain(geosite:cn) -> direct
}`)
	if err != nil {
		return nil, err
	}

	var r config.Routing
	if err := config.SectionParser(reflect.ValueOf(&r), sections[0]); err != nil {
		return nil, err
	}

	rules, err := routing.ApplyRulesOptimizers(
		r.Rules,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{Logger: logrus.StandardLogger(), LocationFinder: assets.NewLocationFinder(nil)},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	)
	if err != nil {
		return nil, fmt.Errorf("ApplyRulesOptimizers error:\n%w", err)
	}

	builder := testRoutingMatcherBuilder{}
	rb := routing.NewRulesBuilder(logrus.StandardLogger())
	rb.RegisterFunctionParser("domain", func(_ *logrus.Logger, f *config_parser.Function, key string, paramValueGroup []string, overrideOutbound *routing.Outbound) error {
		builder.addDomain(f, key, paramValueGroup, overrideOutbound)
		return nil
	})
	if err := rb.Apply(rules); err != nil {
		return nil, fmt.Errorf("Apply: %w", err)
	}
	return builder.simulatedDomainSet, builder.err
}
