/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, v2rayA Organization <team@v2raya.org>
 */

package config

import (
	"bytes"
	"fmt"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/pkg/config_parser"
	"reflect"
	"strconv"
	"strings"
)

// Marshal assume all tokens should be legal, and does not prevent injection attacks.
func (c *Config) Marshal(indentSpace int) (b []byte, err error) {
	m := marshaller{
		indentSpace: indentSpace,
		buf:         new(bytes.Buffer),
	}
	// Root.
	v := reflect.ValueOf(*c)
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		k, ok := t.Field(i).Tag.Lookup("mapstructure")
		if !ok {
			return nil, fmt.Errorf("section %v misses tag mapstructure", t.Field(i).Name)
		}
		if err = m.marshalSection(k, v.Field(i), 0); err != nil {
			return nil, err
		}
	}
	return m.buf.Bytes(), nil
}

type marshaller struct {
	indentSpace int
	buf         *bytes.Buffer
}

func (m *marshaller) writeLine(depth int, line string) {
	m.buf.Write(bytes.Repeat([]byte{' '}, depth*m.indentSpace))
	m.buf.WriteString(line)
	m.buf.WriteString("\n")
}

func (m *marshaller) marshalStringList(from reflect.Value, depth int, keyable bool) (err error) {
	for i := 0; i < from.Len(); i++ {
		str := from.Index(i)
		if keyable {
			tag, afterTag := common.GetTagFromLinkLikePlaintext(str.String())
			if len(tag) > 0 {
				m.writeLine(depth, tag+":"+strconv.Quote(afterTag))
				continue
			}
		}
		m.writeLine(depth, strconv.Quote(str.String()))
	}
	return nil
}
func (m *marshaller) marshalSection(name string, from reflect.Value, depth int) (err error) {
	m.writeLine(depth, name+" {")
	defer m.writeLine(depth, "}")

	switch from.Kind() {
	case reflect.Slice:
		elemType := from.Type().Elem()
		switch elemType.Kind() {
		case reflect.String:
			keyable := false
			switch elemType {
			case reflect.TypeOf(KeyableString("")):
				keyable = true
			default:
			}
			if err = m.marshalStringList(from, depth+1, keyable); err != nil {
				return err
			}
			return nil
		case reflect.Struct:
			// "from" is a section list (sections in section).
			/**
				from {
					field1 {
						...
					}
					field2 {
						...
					}
				}
			should be parsed from:
				from []struct {
						Name string `mapstructure: "_"`
						...
					}
			*/
			// The struct should contain Name.
			nameStructField, ok := elemType.FieldByName("Name")
			if !ok || nameStructField.Type.Kind() != reflect.String || nameStructField.Tag.Get("mapstructure") != "_" {
				return fmt.Errorf("a string field \"Name\" with mapstructure:\"_\" is required in struct %v from parse section", from.Type().Elem().String())
			}
			// Scan sections.
			for i := 0; i < from.Len(); i++ {
				item := from.Index(i)
				nameField := item.FieldByName("Name")
				if nameField.Kind() != reflect.String {
					return fmt.Errorf("name field of section should be string type")
				}
				if err = m.marshalSection(nameField.String(), item, depth+1); err != nil {
					return err
				}
			}
			return nil
		default:
			goto unsupported
		}
	case reflect.Struct:
		// Section.
		return m.marshalParam(from, depth+1)
	default:
		goto unsupported
	}

	panic("code should not reach here")

unsupported:
	return fmt.Errorf("unsupported section type %v", from.Type())
}

func (m *marshaller) marshalLeaf(key string, from reflect.Value, depth int) (err error) {
	if from.IsZero() {
		// Do not marshal zero value.
		return nil
	}
	switch from.Kind() {
	case reflect.Slice:
		if from.Len() == 0 {
			return nil
		}
		switch from.Index(0).Interface().(type) {
		case fmt.Stringer, string,
			uint8, uint16, uint32, uint64,
			int8, int16, int32, int64,
			float32, float64,
			bool:
			var vals []string
			for i := 0; i < from.Len(); i++ {
				vals = append(vals, fmt.Sprintf("%v", from.Index(i).Interface()))
			}
			m.writeLine(depth, key+":"+strconv.Quote(strings.Join(vals, ",")))
		case *config_parser.Function:
			var vals []string
			for i := 0; i < from.Len(); i++ {
				v := from.Index(i).Interface().(*config_parser.Function)
				vals = append(vals, v.String(true, true, false))
			}
			m.writeLine(depth, key+":"+strings.Join(vals, "&&"))
		case KeyableString:
			m.writeLine(depth, key+" {")
			if err = m.marshalStringList(from, depth+1, true); err != nil {
				return err
			}
			m.writeLine(depth, "}")
		default:
			return fmt.Errorf("unknown leaf array type: %v", from.Type())
		}
	default:
		switch val := from.Interface().(type) {
		case fmt.Stringer, string,
			uint8, uint16, uint32, uint64,
			int8, int16, int32, int64,
			float32, float64,
			bool:
			m.writeLine(depth, key+":"+strconv.Quote(fmt.Sprintf("%v", val)))
		case *config_parser.Function:
			m.writeLine(depth, key+":"+val.String(true, true, false))
		default:
			return fmt.Errorf("unknown leaf type: %T", val)
		}
	}
	return nil
}
func (m *marshaller) marshalParam(from reflect.Value, depth int) (err error) {
	if from.Kind() != reflect.Struct {
		return fmt.Errorf("marshalParam can only marshal struct")
	}

	// Marshal section.
	typ := from.Type()
	for i := 0; i < from.NumField(); i++ {
		field := from.Field(i)
		structField := typ.Field(i)

		key, ok := structField.Tag.Lookup("mapstructure")
		if !ok {
			return fmt.Errorf("tag mapstructure is required")
		}
		// Reserved field.
		if key == "_" {
			switch structField.Name {
			case "Name":
			case "Rules":
				// Expand.
				rules, ok := field.Interface().([]*config_parser.RoutingRule)
				if !ok {
					return fmt.Errorf("unexpected Rules type: %v", field.Type())
				}
				for _, r := range rules {
					m.writeLine(depth, r.String(false, true, true))
				}
			default:
				return fmt.Errorf("unknown reserved field: %v", structField.Name)
			}
			continue
		}

		// Section(s) field.
		if field.Kind() == reflect.Struct || (field.Kind() == reflect.Slice &&
			field.Type().Elem().Kind() == reflect.Struct) {
			if err = m.marshalSection(key, field, depth); err != nil {
				return err
			}
			continue
		}

		// Normal field.
		if err = m.marshalLeaf(key, field, depth); err != nil {
			return err
		}
	}

	return nil
}
