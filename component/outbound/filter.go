/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package outbound

import (
	"fmt"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"github.com/v2rayA/dae/pkg/config_parser"
	"regexp"
	"strings"
)

const (
	FilterInput_Name            = "name"
	FilterInput_SubscriptionTag = "subtag"
	FilterInput_Link            = "link"
)

const (
	FilterKey_Name_Regex   = "regex"
	FilterKey_Name_Keyword = "keyword"

	FilterInput_SubscriptionTag_Regex = "regex"
)

type DialerSet struct {
	dialers      []*dialer.Dialer
	nodeToTagMap map[*dialer.Dialer]string
}

func NewDialerSetFromLinks(option *dialer.GlobalOption, tagToNodeList map[string][]string) *DialerSet {
	s := &DialerSet{
		dialers:      make([]*dialer.Dialer, 0),
		nodeToTagMap: make(map[*dialer.Dialer]string),
	}
	for subscriptionTag, nodes := range tagToNodeList {
		for _, node := range nodes {
			d, err := dialer.NewFromLink(option, dialer.InstanceOption{CheckEnabled: false}, node)
			if err != nil {
				option.Log.Infof("failed to parse node: %v: %v", node, err)
				continue
			}
			s.dialers = append(s.dialers, d)
			s.nodeToTagMap[d] = subscriptionTag
		}
	}
	return s
}

func (s *DialerSet) filterHit(dialer *dialer.Dialer, filters []*config_parser.Function) (hit bool, err error) {
	if len(filters) == 0 {
		// No filter.
		return true, nil
	}

	// Example
	// filter: name(regex:'^.*hk.*$', keyword:'sg') && name(keyword:'disney')
	// filter: !name(regex: 'HK|TW|SG') && name(keyword: disney)
	// filter: subtag(my_sub, regex:^my_, regex:my_)

	// And
	for _, filter := range filters {
		var subFilterHit bool

		switch filter.Name {
		case FilterInput_Name:
			// Or
			for _, param := range filter.Params {
				switch param.Key {
				case FilterKey_Name_Regex:
					matched, _ := regexp.MatchString(param.Val, dialer.Name())
					//logrus.Warnln(param.Val, matched, dialer.Name())
					if matched {
						subFilterHit = true
						break
					}
				case FilterKey_Name_Keyword:
					if strings.Contains(dialer.Name(), param.Val) {
						subFilterHit = true
						break
					}
				case "":
					if dialer.Name() == param.Val {
						subFilterHit = true
						break
					}
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
				}
			}
		case FilterInput_SubscriptionTag:
			// Or
			for _, param := range filter.Params {
				switch param.Key {
				case FilterInput_SubscriptionTag_Regex:
					matched, _ := regexp.MatchString(param.Val, s.nodeToTagMap[dialer])
					//logrus.Warnln(param.Val, matched, dialer.Name())
					if matched {
						subFilterHit = true
						break
					}
				case "":
					// Full
					if s.nodeToTagMap[dialer] == param.Val {
						subFilterHit = true
						break
					}
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
				}
			}

		default:
			return false, fmt.Errorf(`unsupported filter input type: "%v"`, filter.Name)
		}

		if subFilterHit == filter.Not {
			return false, nil
		}
	}
	return true, nil
}

func (s *DialerSet) Filter(filters []*config_parser.Function) (dialers []*dialer.Dialer, err error) {
	for _, d := range s.dialers {
		hit, err := s.filterHit(d, filters)
		if err != nil {
			return nil, err
		}
		if hit {
			dialers = append(dialers, d)
		}
	}
	return dialers, nil
}
