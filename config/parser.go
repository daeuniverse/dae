/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"reflect"
	"strings"
)

func StringListParser(to reflect.Value, section *config_parser.Section) error {
	if to.Kind() != reflect.Pointer {
		return fmt.Errorf("StringListParser can only unmarshal section to *[]string")
	}
	to = to.Elem()
	if to.Type() != reflect.TypeOf([]string{}) &&
		!(to.Kind() == reflect.Slice && to.Type().Elem().Kind() == reflect.String) {
		return fmt.Errorf("StringListParser can only unmarshal section to *[]string")
	}
	for _, item := range section.Items {
		switch itemVal := item.Value.(type) {
		case *config_parser.Param:
			to.Set(reflect.Append(to, reflect.ValueOf(itemVal.String(true, false)).Convert(to.Type().Elem())))
		default:
			return fmt.Errorf("section %v does not support type %v: %v", section.Name, item.Type.String(), item.String(false, false))
		}
	}
	return nil
}

func ParamParser(to reflect.Value, section *config_parser.Section, ignoreType []reflect.Type) error {
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
			return fmt.Errorf("field \"%v\" has no mapstructure tag", structField.Name)
		}
		if key == "_" {
			// omit
			continue
		}
		keyToField[key] = &Field{Val: field, Index: i}

		// Fill in default value before parsing section.
		defaultValue, ok := structField.Tag.Lookup("default")
		if ok {
			// Can we assign?
			if field.Kind() == reflect.Interface ||
				field.Type() == reflect.TypeOf(defaultValue) {
				field.Set(reflect.ValueOf(defaultValue))

				// Can we fuzzy decode?
			} else if !common.FuzzyDecode(field.Addr().Interface(), defaultValue) {
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
				return fmt.Errorf("unsupported text without a key: %v", itemVal.String(true, false))
			}
			field, ok := keyToField[itemVal.Key]
			if !ok {
				return fmt.Errorf("unexpected key: %v", itemVal.Key)
			}
			if itemVal.AndFunctions != nil {
				// AndFunctions.
				// If field is interface{} or types equal, we can assign.
				if field.Val.Kind() == reflect.Interface ||
					field.Val.Type() == reflect.TypeOf(itemVal.AndFunctions) {
					field.Val.Set(reflect.ValueOf(itemVal.AndFunctions))
				} else {
					return fmt.Errorf("failed to parse \"%v\": value \"%v\" cannot be convert to %v", itemVal.Key, itemVal.Val, field.Val.Type().String())
				}
			} else {
				// String value.
				switch field.Val.Kind() {
				case reflect.Interface:
					// Field is interface{}, we can assign.
					field.Val.Set(reflect.ValueOf(itemVal.Val))
				case reflect.Slice:
					// Field is not interface{}, we can decode.
					values := strings.Split(itemVal.Val, ",")
					for _, value := range values {
						vPointerNew := reflect.New(field.Val.Type().Elem())
						if !common.FuzzyDecode(vPointerNew.Interface(), value) {
							return fmt.Errorf("failed to parse \"%v\": value \"%v\" cannot be convert to %v", itemVal.Key, itemVal.Val, field.Val.Type().Elem().String())
						}
						field.Val.Set(reflect.Append(field.Val, vPointerNew.Elem()))
					}
				default:
					// Field is not interface{}, we can decode.
					if !common.FuzzyDecode(field.Val.Addr().Interface(), itemVal.Val) {
						return fmt.Errorf("failed to parse \"%v\": value \"%v\" cannot be convert to %v", itemVal.Key, itemVal.Val, field.Val.Type().String())
					}
				}
			}
			field.Set = true
		case *config_parser.Section:
			// Named section config item.
			field, ok := keyToField[itemVal.Name]
			if !ok {
				return fmt.Errorf("unexpected key: %v", itemVal.Name)
			}
			if err := SectionParser(field.Val.Addr(), itemVal); err != nil {
				return fmt.Errorf("failed to parse %v: %w", itemVal.Name, err)
			}
			field.Set = true
		case *config_parser.RoutingRule:
			// Assign. "to" should have field "Rules".
			structField, ok := to.Type().FieldByName("Rules")
			if !ok || structField.Type != reflect.TypeOf([]*config_parser.RoutingRule{}) {
				return fmt.Errorf("unexpected type: \"routing rule\": %v", itemVal.String(true, false, false))
			}
			if structField.Tag.Get("mapstructure") != "_" {
				return fmt.Errorf("a []*RoutingRule field \"Rules\" with mapstructure:\"_\" is required in struct %v to parse section", to.Type().String())
			}
			field := to.FieldByName("Rules")
			field.Set(reflect.Append(field, reflect.ValueOf(itemVal)))
		default:
			if _, ignore := ignoreTypeSet[reflect.TypeOf(itemVal)]; !ignore {
				return fmt.Errorf("unexpected type %v: %v", item.Type.String(), item.String(false, false))
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

func SectionParser(to reflect.Value, section *config_parser.Section) error {
	if to.Kind() != reflect.Pointer {
		return fmt.Errorf("SectionParser can only unmarshal section to a pointer")
	}
	to = to.Elem()
	switch to.Kind() {
	case reflect.Slice:
		elemType := to.Type().Elem()
		switch elemType.Kind() {
		case reflect.String:
			return StringListParser(to.Addr(), section)
		case reflect.Struct:
			// "to" is a section list (sections in section).
			/**
				to {
					field1 {
						...
					}
					field2 {
						...
					}
				}
			should be parsed to:
				to []struct {
						Name string `mapstructure: "_"`
						...
					}
			*/
			// The struct should contain Name.
			nameStructField, ok := elemType.FieldByName("Name")
			if !ok || nameStructField.Type.Kind() != reflect.String || nameStructField.Tag.Get("mapstructure") != "_" {
				return fmt.Errorf("a string field \"Name\" with mapstructure:\"_\" is required in struct %v to parse section", to.Type().Elem().String())
			}
			// Scan sections.
			for _, item := range section.Items {
				elem := reflect.New(elemType).Elem()
				switch itemVal := item.Value.(type) {
				case *config_parser.Section:
					elem.FieldByName("Name").SetString(itemVal.Name)
					if err := SectionParser(elem.Addr(), itemVal); err != nil {
						return fmt.Errorf("error when parse \"%v\": %w", itemVal.Name, err)
					}
					to.Set(reflect.Append(to, elem))
				default:
					return fmt.Errorf("unmatched type: %v -> %v", item.Type.String(), elemType)
				}
			}
			return nil
		default:
			goto unsupported
		}
	case reflect.Struct:
		// Section.
		return ParamParser(to.Addr(), section, nil)
	default:
		goto unsupported
	}

	panic("code should not reach here")

unsupported:
	return fmt.Errorf("unsupported section type %v", to.Type())
}
