/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package routing

import (
	"fmt"
	"github.com/v2rayA/dae/common/assets"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/pkg/geodata"
	"github.com/sirupsen/logrus"
	"net/netip"
	"sort"
	"strings"
)
import "github.com/mohae/deepcopy"

type RulesOptimizer interface {
	Optimize(rules []RoutingRule) ([]RoutingRule, error)
}

func DeepCloneRules(rules []RoutingRule) (newRules []RoutingRule) {
	return deepcopy.Copy(rules).([]RoutingRule)
}

func ApplyRulesOptimizers(rules []RoutingRule, optimizers ...RulesOptimizer) ([]RoutingRule, error) {
	rules = DeepCloneRules(rules)
	var err error
	for _, opt := range optimizers {
		if rules, err = opt.Optimize(rules); err != nil {
			return nil, err
		}
	}
	return rules, err
}

type RefineFunctionParamKeyOptimizer struct {
}

func (o *RefineFunctionParamKeyOptimizer) Optimize(rules []RoutingRule) ([]RoutingRule, error) {
	for _, rule := range rules {
		for _, function := range rule.AndFunctions {
			for _, param := range function.Params {
				switch function.Name {
				case "domain":
					// Rewrite to authoritative key name.
					switch param.Key {
					case "", "domain":
						param.Key = consts.RoutingDomain_Suffix
					case "contains":
						param.Key = consts.RoutingDomain_Keyword
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

func (o *MergeAndSortRulesOptimizer) Optimize(rules []RoutingRule) ([]RoutingRule, error) {
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
	var newRules []RoutingRule
	mergingRule := rules[0]
	for i := 1; i < len(rules); i++ {
		if len(mergingRule.AndFunctions) == 1 &&
			len(rules[i].AndFunctions) == 1 &&
			mergingRule.AndFunctions[0].Name == rules[i].AndFunctions[0].Name &&
			rules[i].Outbound == mergingRule.Outbound {
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
			if function.Name == "ip" {
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

func deduplicateParams(list []*Param) []*Param {
	res := make([]*Param, 0, len(list))
	m := make(map[Param]struct{})
	for _, v := range list {
		if _, ok := m[*v]; ok {
			continue
		}
		m[*v] = struct{}{}
		res = append(res, v)
	}
	return res
}

func (o *DeduplicateParamsOptimizer) Optimize(rules []RoutingRule) ([]RoutingRule, error) {
	for _, rule := range rules {
		for _, f := range rule.AndFunctions {
			f.Params = deduplicateParams(f.Params)
		}
	}
	return rules, nil
}

type DatReaderOptimizer struct {
	Logger *logrus.Logger
}

func (o *DatReaderOptimizer) loadGeoSite(filename string, code string) (params []*Param, err error) {
	if !strings.HasSuffix(filename, ".dat") {
		filename += ".dat"
	}
	filePath, err := assets.GetLocationAsset(filename)
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
			params = append(params, &Param{
				Key: consts.RoutingDomain_Full,
				Val: item.Value,
			})
		case geodata.Domain_RootDomain:
			// Suffix.
			params = append(params, &Param{
				Key: consts.RoutingDomain_Suffix,
				Val: item.Value,
			})
		case geodata.Domain_Plain:
			// Keyword.
			params = append(params, &Param{
				Key: consts.RoutingDomain_Keyword,
				Val: item.Value,
			})
		case geodata.Domain_Regex:
			// Regex.
			params = append(params, &Param{
				Key: consts.RoutingDomain_Regex,
				Val: item.Value,
			})
		}
	}
	return params, nil
}

func (o *DatReaderOptimizer) loadGeoIp(filename string, code string) (params []*Param, err error) {
	if !strings.HasSuffix(filename, ".dat") {
		filename += ".dat"
	}
	filePath, err := assets.GetLocationAsset(filename)
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
	for _, item := range geoIp.Cidr {
		ip, ok := netip.AddrFromSlice(item.Ip)
		if !ok {
			return nil, fmt.Errorf("bad geoip file: %v", filename)
		}
		params = append(params, &Param{
			Key: "",
			Val: netip.PrefixFrom(ip, int(item.Prefix)).String(),
		})
	}
	return params, nil
}

func (o *DatReaderOptimizer) Optimize(rules []RoutingRule) ([]RoutingRule, error) {
	var err error
	for _, rule := range rules {
		for _, f := range rule.AndFunctions {
			var newParams []*Param
			for _, param := range f.Params {
				// Parse this param and replace it with more.
				var params []*Param
				switch param.Key {
				case "geosite":
					params, err = o.loadGeoSite("geosite", param.Val)
				case "geoip":
					params, err = o.loadGeoIp("geoip", param.Val)
				case "dat":
					fields := strings.SplitN(param.Val, ":", 2)
					switch f.Name {
					case consts.Function_Domain:
						params, err = o.loadGeoSite(fields[0], fields[1])
					case consts.Function_Ip:
						params, err = o.loadGeoIp(fields[0], fields[1])
					}
				default:
					// Keep this param.
					params = []*Param{param}
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
