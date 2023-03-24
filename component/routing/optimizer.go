/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"fmt"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/mohae/deepcopy"
	"github.com/sirupsen/logrus"
	"net/netip"
	"sort"
	"strings"
)

type RulesOptimizer interface {
	Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error)
}

func DeepCloneRules(rules []*config_parser.RoutingRule) (newRules []*config_parser.RoutingRule) {
	return deepcopy.Copy(rules).([]*config_parser.RoutingRule)
}

func ApplyRulesOptimizers(rules []*config_parser.RoutingRule, optimizers ...RulesOptimizer) ([]*config_parser.RoutingRule, error) {
	rules = DeepCloneRules(rules)
	var err error
	for _, opt := range optimizers {
		if rules, err = opt.Optimize(rules); err != nil {
			return nil, err
		}
	}
	return rules, err
}

type AliasOptimizer struct {
}

func (o *AliasOptimizer) Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error) {
	for _, rule := range rules {
		for _, function := range rule.AndFunctions {
			switch function.Name {
			case "dport":
				function.Name = consts.Function_Port
			case "dip":
				function.Name = consts.Function_Ip
			}
			for _, param := range function.Params {
				switch function.Name {
				case consts.Function_Domain:
					// Rewrite to authoritative key name.
					switch param.Key {
					case "", "domain":
						param.Key = string(consts.RoutingDomainKey_Suffix)
					case "contains":
						param.Key = string(consts.RoutingDomainKey_Keyword)
					default:
					}
				}
			}
		}
	}
	return rules, nil
}

type MergeAndSortRulesOptimizer struct {
}

func (o *MergeAndSortRulesOptimizer) Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error) {
	if len(rules) == 0 {
		return rules, nil
	}
	// Sort AndFunctions by FunctionName.
	for _, rule := range rules {
		sort.SliceStable(rule.AndFunctions, func(i, j int) bool {
			return rule.AndFunctions[i].Name < rule.AndFunctions[j].Name
		})
	}
	// Merge singleton rules with the same outbound.
	var newRules []*config_parser.RoutingRule
	mergingRule := rules[0]
	for i := 1; i < len(rules); i++ {
		if len(mergingRule.AndFunctions) == 1 &&
			len(rules[i].AndFunctions) == 1 &&
			mergingRule.AndFunctions[0].Name == rules[i].AndFunctions[0].Name &&
			rules[i].Outbound.String(true, false, true) == mergingRule.Outbound.String(true, false, true) {
			mergingRule.AndFunctions[0].Params = append(mergingRule.AndFunctions[0].Params, rules[i].AndFunctions[0].Params...)
		} else {
			newRules = append(newRules, mergingRule)
			mergingRule = rules[i]
		}
	}
	newRules = append(newRules, mergingRule)
	// Sort ParamList.
	for i := range newRules {
		for _, function := range newRules[i].AndFunctions {
			if function.Name == consts.Function_Ip || function.Name == consts.Function_SourceIp {
				// Sort by IPv4, IPv6, vals.
				sort.SliceStable(function.Params, func(i, j int) bool {
					vi, vj := 4, 4
					if strings.Contains(function.Params[i].Val, ":") {
						vi = 6
					}
					if strings.Contains(function.Params[j].Val, ":") {
						vj = 6
					}
					if vi == vj {
						return function.Params[i].Val < function.Params[j].Val
					}
					return vi < vj
				})
			} else {
				// Sort by keys, vals.
				sort.SliceStable(function.Params, func(i, j int) bool {
					if function.Params[i].Key == function.Params[j].Key {
						return function.Params[i].Val < function.Params[j].Val
					}
					return function.Params[i].Key < function.Params[j].Key
				})
			}
		}
	}
	return newRules, nil
}

type DeduplicateParamsOptimizer struct {
}

func deduplicateParams(list []*config_parser.Param) []*config_parser.Param {
	res := make([]*config_parser.Param, 0, len(list))
	m := make(map[string]struct{})
	for _, v := range list {
		if _, ok := m[v.String(true, false)]; ok {
			continue
		}
		m[v.String(true, false)] = struct{}{}
		res = append(res, v)
	}
	return res
}

func (o *DeduplicateParamsOptimizer) Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error) {
	for _, rule := range rules {
		for _, f := range rule.AndFunctions {
			f.Params = deduplicateParams(f.Params)
		}
	}
	return rules, nil
}

type DatReaderOptimizer struct {
	LocationFinder *assets.LocationFinder
	Logger         *logrus.Logger
}

func (o *DatReaderOptimizer) loadGeoSite(filename string, code string) (params []*config_parser.Param, err error) {
	if !strings.HasSuffix(filename, ".dat") {
		filename += ".dat"
	}
	filePath, err := o.LocationFinder.GetLocationAsset(o.Logger, filename)
	if err != nil {
		o.Logger.Debugf("Failed to read geosite \"%v:%v\": %v", filename, code, err)
		return nil, err
	}
	o.Logger.Debugf("Read geosite \"%v:%v\" from %v", filename, code, filePath)
	geoSite, err := geodata.UnmarshalGeoSite(o.Logger, filePath, code)
	if err != nil {
		return nil, err
	}
	for _, item := range geoSite.Domain {
		switch item.Type {
		case geodata.Domain_Full:
			// Full.
			params = append(params, &config_parser.Param{
				Key: string(consts.RoutingDomainKey_Full),
				Val: item.Value,
			})
		case geodata.Domain_RootDomain:
			// Suffix.
			params = append(params, &config_parser.Param{
				Key: string(consts.RoutingDomainKey_Suffix),
				Val: item.Value,
			})
		case geodata.Domain_Plain:
			// Keyword.
			params = append(params, &config_parser.Param{
				Key: string(consts.RoutingDomainKey_Keyword),
				Val: item.Value,
			})
		case geodata.Domain_Regex:
			// Regex.
			params = append(params, &config_parser.Param{
				Key: string(consts.RoutingDomainKey_Regex),
				Val: item.Value,
			})
		}
	}
	return params, nil
}

func (o *DatReaderOptimizer) loadGeoIp(filename string, code string) (params []*config_parser.Param, err error) {
	if !strings.HasSuffix(filename, ".dat") {
		filename += ".dat"
	}
	filePath, err := o.LocationFinder.GetLocationAsset(o.Logger, filename)
	if err != nil {
		o.Logger.Debugf("Failed to read geoip \"%v:%v\": %v", filename, code, err)
		return nil, err
	}
	o.Logger.Debugf("Read geoip \"%v:%v\" from %v", filename, code, filePath)
	geoIp, err := geodata.UnmarshalGeoIp(o.Logger, filePath, code)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if geoIp.InverseMatch {
		return nil, fmt.Errorf("not support inverse match yet")
	}
	for _, item := range geoIp.Cidr {
		ip, ok := netip.AddrFromSlice(item.Ip)
		if !ok {
			return nil, fmt.Errorf("bad geoip file: %v", filename)
		}
		params = append(params, &config_parser.Param{
			Key: "",
			Val: netip.PrefixFrom(ip, int(item.Prefix)).String(),
		})
	}
	return params, nil
}

func (o *DatReaderOptimizer) Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error) {
	var err error
	for _, rule := range rules {
		for _, f := range rule.AndFunctions {
			var newParams []*config_parser.Param
			for _, param := range f.Params {
				// Parse this param and replace it with more.
				var params []*config_parser.Param
				switch param.Key {
				case "geosite":
					params, err = o.loadGeoSite("geosite", param.Val)
				case "geoip":
					params, err = o.loadGeoIp("geoip", param.Val)
				case "ext":
					fields := strings.SplitN(param.Val, ":", 2)
					switch f.Name {
					case consts.Function_Domain, consts.Function_QName:
						params, err = o.loadGeoSite(fields[0], fields[1])
					case consts.Function_Ip:
						params, err = o.loadGeoIp(fields[0], fields[1])
					default:
						return nil, fmt.Errorf("unsupported extension file extraction in function %v", f.Name)
					}
				default:
					// Keep this param.
					params = []*config_parser.Param{param}
				}
				if err != nil {
					return nil, err
				}
				newParams = append(newParams, params...)
				f.Params = newParams
			}
		}
	}
	return rules, nil
}
