/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"text/template"
)

type ProgField struct {
	Name string
	Ebpf string
}

//go:embed bpf_subobjects.tmpl
var tmpl []byte

func generate(output string) error {
	var lanProgFields []ProgField
	var wanProgFields []ProgField
	tBpfProg := reflect.ValueOf(bpfObjects{}).FieldByName("bpfPrograms").Type()
	for i := 0; i < tBpfProg.NumField(); i++ {
		structField := tBpfProg.Field(i)
		switch {
		case strings.HasPrefix(structField.Name, "TproxyLan"):
			lanProgFields = append(lanProgFields, ProgField{
				Name: structField.Name,
				Ebpf: structField.Tag.Get("ebpf"),
			})
		case strings.HasPrefix(structField.Name, "TproxyWan"):
			wanProgFields = append(wanProgFields, ProgField{
				Name: structField.Name,
				Ebpf: structField.Tag.Get("ebpf"),
			})
		default:
			return fmt.Errorf("unexpected program name which should begin with TproxyWan or TproxyLan, but get: %v", structField.Name)
		}
	}

	t, err := template.New("").Parse(string(tmpl))
	if err != nil {
		return err
	}
	f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	abs, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	fmt.Printf("Write to %v\n", abs)
	if err = t.Execute(f, map[string]interface{}{
		"WanProgFields": wanProgFields,
		"LanProgFields": lanProgFields,
	}); err != nil {
		return err
	}
	return nil
}

func GenerateObjects(output string) {
	if err := generate(output); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
