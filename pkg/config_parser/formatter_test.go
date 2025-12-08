/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"strings"
	"testing"
)

func formatWithSpaces(input string) (string, error) {
	return FormatWithIndent(input, strings.Repeat(" ", 4))
}

func TestFormatComments(t *testing.T) {
	// Trims spaces around the comment, but respect spaces inside the comment
	input := "#      comment with spaces surrounding        \n" + strings.TrimSpace(`
routing {
/*
    weird
indented comment
*/
}`)
	expected := strings.TrimSpace(`
#      comment with spaces surrounding
routing {
    /*
    weird
    indented comment
    */
}
`)
	output, err := formatWithSpaces(input)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if output != expected {
		t.Errorf("Expected:\n%q\nGot:\n%q", expected, output)
	}
}

func TestFormatBasic(t *testing.T) {
	input := strings.TrimSpace(`
global{key:val
list: a,b, c [annotation:value1, annotation:value2]
nested { key: val }
'bare_literal'
}
routing     {
pname(NetworkManager)->direct
dip(geoip:        cn,10.0.0/8)-> direct}
`)
	expected := strings.TrimSpace(`
global {
    key: val
    list: a, b, c [annotation: value1, annotation: value2]
    nested {
        key: val
    }
    'bare_literal'
}

routing {
    pname(NetworkManager) -> direct
    dip(geoip:cn, 10.0.0/8) -> direct
}
`)

	output, err := formatWithSpaces(input)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if output != expected {
		t.Errorf("Expected:\n%q\nGot:\n%q", expected, output)
	}
}

func TestFormatInlineComments(t *testing.T) {
	input := strings.TrimSpace(`
# Header
global {
# Indented comment
    key: val # Inline
}
`)
	expected := strings.TrimSpace(`
# Header
global {
    # Indented comment
    key: val # Inline
}
`)

	output, err := formatWithSpaces(input)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if output != expected {
		t.Errorf("Expected:\n%q\nGot:\n%q", expected, output)
	}
}

func TestMultiLineRules(t *testing.T) {
	// For multiple line rules:
	// If there is space (or other hidden tokens) between the parenthesis and the parameter
	// formatter should make a line break like the domain rule (add a line break before and after the parenthesis)
	// and add automatic indent for each line
	// Otherwise, formatter should only make automatic indent for each rule line break (like the dip rule)
	input := strings.TrimSpace(`
routing {
    domain(
    keyword:foo, keyword:bar,
    # geosite:baz,
    geosite:qux) -> direct
    dip(geoip:cn,
    10.0.0/8) -> direct
}`)
	// Note: arguments like keyword:foo do NOT have space after colon because they are parameters, not block declarations.
	// Comments are normalized to have space after #.
	expected := strings.TrimSpace(`
routing {
    domain(
        keyword:foo, keyword:bar,
        # geosite:baz,
        geosite:qux) -> direct
    dip(geoip:cn,
        10.0.0/8) -> direct
}
`)

	output, err := formatWithSpaces(input)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if output != expected {
		t.Errorf("Expected:\n%q\nGot:\n%q", expected, output)
	}
}
