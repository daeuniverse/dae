/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/dlclark/regexp2"
	"github.com/sirupsen/logrus"
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
	log          *logrus.Logger
	dialers      []*dialer.Dialer
	nodeToTagMap map[*dialer.Dialer]string
}

func NewDialerSetFromLinks(option *dialer.GlobalOption, tagToNodeList map[string][]string) *DialerSet {
	s := &DialerSet{
		log:          option.Log,
		dialers:      make([]*dialer.Dialer, 0),
		nodeToTagMap: make(map[*dialer.Dialer]string),
	}
	for subscriptionTag, nodes := range tagToNodeList {
		for _, node := range nodes {
			d, err := dialer.NewFromLink(option, dialer.InstanceOption{DisableCheck: false}, node, subscriptionTag)
			if err != nil {
				s.log.Infof("failed to parse node: %v", err)
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
		loop:
			for _, param := range filter.Params {
				switch param.Key {
				case FilterKey_Name_Regex:
					regex, err := regexp2.Compile(param.Val, 0)
					if err != nil {
						return false, fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
					}
					matched, _ := regex.MatchString(dialer.Property().Name)
					//logrus.Warnln(param.Val, matched, dialer.Name())
					if matched {
						subFilterHit = true
						break loop
					}
				case FilterKey_Name_Keyword:
					if strings.Contains(dialer.Property().Name, param.Val) {
						subFilterHit = true
						break loop
					}
				case "":
					if dialer.Property().Name == param.Val {
						subFilterHit = true
						break loop
					}
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
				}
			}
		case FilterInput_SubscriptionTag:
			// Or
		loop2:
			for _, param := range filter.Params {
				switch param.Key {
				case FilterInput_SubscriptionTag_Regex:
					regex, err := regexp2.Compile(param.Val, 0)
					if err != nil {
						return false, fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
					}
					matched, _ := regex.MatchString(s.nodeToTagMap[dialer])
					if matched {
						subFilterHit = true
						break loop2
					}
					//logrus.Warnln(param.Val, matched, dialer.Name())
				case "":
					// Full
					if s.nodeToTagMap[dialer] == param.Val {
						subFilterHit = true
						break loop2
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

func (s *DialerSet) FilterAndAnnotate(filters [][]*config_parser.Function, annotations [][]*config_parser.Param) (dialers []*dialer.Dialer, filterAnnotations []*dialer.Annotation, err error) {
	if len(filters) != len(annotations) {
		return nil, nil, fmt.Errorf("[CODE BUG]: unmatched annotations length: %v filters and %v annotations", len(filters), len(annotations))
	}
	if len(filters) == 0 {
		anno := make([]*dialer.Annotation, len(s.dialers))
		for i := range anno {
			anno[i] = &dialer.Annotation{}
		}
		return s.dialers, anno, nil
	}
nextDialerLoop:
	for _, d := range s.dialers {
		// Hit any.
		for j, f := range filters {
			hit, err := s.filterHit(d, f)
			if err != nil {
				return nil, nil, err
			}
			if hit {
				anno, err := dialer.NewAnnotation(annotations[j])
				if err != nil {
					return nil, nil, fmt.Errorf("apply filter annotation: %w", err)
				}
				dialers = append(dialers, d)
				filterAnnotations = append(filterAnnotations, anno)
				continue nextDialerLoop
			}
		}
	}
	return dialers, filterAnnotations, nil
}

func (s *DialerSet) Close() error {
	var err error
	for _, d := range s.dialers {
		if e := d.Close(); e != nil {
			err = e
		}
	}
	return err
}
