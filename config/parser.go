/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package config

import (
	"fmt"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/pkg/config_parser"
	"reflect"
)

// Parser is section items parser
type Parser func(to reflect.Value, section *config_parser.Section) error

var ParserMap = map[string]Parser{
	"StringListParser":          StringListParser,
	"ParamParser":               ParamParser,
	"GroupListParser":           GroupListParser,
	"RoutingRuleAndParamParser": RoutingRuleAndParamParser,
}

func StringListParser(to reflect.Value, section *config_parser.Section) error {
	if to.Kind() != reflect.Pointer {
		return fmt.Errorf("StringListParser can only unmarshal section to *[]string")
	}
	to = to.Elem()
	if to.Type() != reflect.TypeOf([]string{}) {
		return fmt.Errorf("StringListParser can only unmarshal section to *[]string")
	}
	var list []string
	for _, item := range section.Items {
		switch itemVal := item.Value.(type) {
		case *config_parser.Param:
			list = append(list, itemVal.String(true))
		default:
			return fmt.Errorf("section %v does not support type %v: %v", section.Name, item.Type.String(), item.String())
		}
	}
	to.Set(reflect.ValueOf(list))
	return nil
}

func paramParser(to reflect.Value, section *config_parser.Section, ignoreType []reflect.Type) error {
	if to.Kind() != reflect.Pointer {
		return fmt.Errorf("ParamParser can only unmarshal section to *struct")
	}
	to = to.Elem()
	if to.Kind() != reflect.Struct {
		return fmt.Errorf("ParamParser can only unmarshal section to struct")
	}

	// keyToField is for further parsing use.
	type Field struct {
		Val   reflect.Value
		Index int
		Set   bool
	}
	var keyToField = make(map[string]*Field)
	tot := to.Type()
	for i := 0; i < to.NumField(); i++ {
		field := to.Field(i)
		structField := tot.Field(i)
		// Set up key to field mapping.
		key, ok := structField.Tag.Lookup("mapstructure")
		if !ok {
			return fmt.Errorf("field %v has no mapstructure tag", structField.Name)
		}
		if key == "_" {
			// omit
			continue
		}
		keyToField[key] = &Field{Val: field, Index: i}

		// Fill in default value before parsing section.
		defaultValue, ok := structField.Tag.Lookup("default")
		if ok {
			if !common.FuzzyDecode(field.Addr().Interface(), defaultValue) {
				return fmt.Errorf(`failed to decode default value of "%v"`, structField.Name)
			}
		}
	}

	// Convert ignoreType from list to set.
	ignoreTypeSet := make(map[reflect.Type]struct{})
	for _, typ := range ignoreType {
		ignoreTypeSet[typ] = struct{}{}
	}

	// Parse section.
	for _, item := range section.Items {
		switch itemVal := item.Value.(type) {
		case *config_parser.Param:
			if itemVal.Key == "" {
				return fmt.Errorf("section %v does not support text without a key: %v", section.Name, itemVal.String(true))
			}
			field, ok := keyToField[itemVal.Key]
			if !ok {
				return fmt.Errorf("section %v does not support key: %v", section.Name, itemVal.Key)
			}
			if itemVal.AndFunctions != nil {
				// AndFunctions.
				// If field is interface{} or types equal, we can assign.
				if field.Val.Kind() == reflect.Interface ||
					field.Val.Type() == reflect.TypeOf(itemVal.AndFunctions) {
					field.Val.Set(reflect.ValueOf(itemVal.AndFunctions))
				} else {
					return fmt.Errorf("failed to parse \"%v.%v\": value \"%v\" cannot be convert to %v", section.Name, itemVal.Key, itemVal.Val, field.Val.Type().String())
				}
			} else {
				// String value.
				if field.Val.Kind() == reflect.Interface {
					// Field is interface{}, we can assign.
					field.Val.Set(reflect.ValueOf(itemVal.Val))
				} else {
					// Field is not interface{}, we can decode.
					if !common.FuzzyDecode(field.Val.Addr().Interface(), itemVal.Val) {
						return fmt.Errorf("failed to parse \"%v.%v\": value \"%v\" cannot be convert to %v", section.Name, itemVal.Key, itemVal.Val, field.Val.Type().String())
					}
				}
			}
			field.Set = true
		default:
			if _, ignore := ignoreTypeSet[reflect.TypeOf(itemVal)]; !ignore {
				return fmt.Errorf("section %v does not support type %v: %v", section.Name, item.Type.String(), item.String())
			}
		}
	}

	// Check required.
	for key, field := range keyToField {
		if field.Set {
			continue
		}
		t := to.Type().Field(field.Index)
		_, required := t.Tag.Lookup("required")
		if required {
			return fmt.Errorf(`section "%v" requires param "%v" but not found`, section.Name, key)
		}
	}
	return nil
}

func ParamParser(to reflect.Value, section *config_parser.Section) error {
	return paramParser(to, section, nil)
}

func GroupListParser(to reflect.Value, section *config_parser.Section) error {
	if to.Kind() != reflect.Pointer {
		return fmt.Errorf("GroupListParser can only unmarshal section to *[]Group")
	}
	to = to.Elem()
	if to.Type() != reflect.TypeOf([]Group{}) {
		return fmt.Errorf("GroupListParser can only unmarshal section to *[]Group")
	}

	for _, item := range section.Items {
		switch itemVal := item.Value.(type) {
		case *config_parser.Section:
			group := Group{
				Name:  itemVal.Name,
				Param: GroupParam{},
			}
			paramVal := reflect.ValueOf(&group.Param)
			if err := paramParser(paramVal, itemVal, nil); err != nil {
				return fmt.Errorf("failed to parse \"%v\": %w", itemVal.Name, err)
			}
			to.Set(reflect.Append(to, reflect.ValueOf(group)))
		default:
			return fmt.Errorf("section %v does not support type %v: %v", section.Name, item.Type.String(), item.String())
		}
	}
	return nil
}

func RoutingRuleAndParamParser(to reflect.Value, section *config_parser.Section) error {
	if to.Kind() != reflect.Pointer {
		return fmt.Errorf("RoutingRuleAndParamParser can only unmarshal section to *struct")
	}
	to = to.Elem()
	if to.Kind() != reflect.Struct {
		return fmt.Errorf("RoutingRuleAndParamParser can only unmarshal section to *struct")
	}

	// Find the first  []*RoutingRule field to unmarshal.
	targetType := reflect.TypeOf([]*config_parser.RoutingRule{})
	var ruleTo *reflect.Value
	for i := 0; i < to.NumField(); i++ {
		field := to.Field(i)

		if field.Type() == targetType {
			ruleTo = &field
			break
		}
	}
	if ruleTo == nil {
		return fmt.Errorf(`no %v field found`, targetType.String())
	}

	// Parse and unmarshal list of RoutingRule to ruleTo.
	for _, item := range section.Items {
		switch itemVal := item.Value.(type) {
		case *config_parser.RoutingRule:
			ruleTo.Set(reflect.Append(*ruleTo, reflect.ValueOf(itemVal)))
		case *config_parser.Param:
			// pass
		default:
			return fmt.Errorf("section %v does not support type %v: %v", section.Name, item.Type.String(), item.String())
		}
	}

	// Parse Param.
	return paramParser(to.Addr(), section,
		[]reflect.Type{reflect.TypeOf(&config_parser.RoutingRule{})},
	)
}
