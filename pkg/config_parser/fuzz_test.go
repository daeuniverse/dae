package config_parser

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func FuzzFormatter(f *testing.F) {
	// Add example.dae as seed
	if content, err := os.ReadFile("../../example.dae"); err == nil {
		f.Add(string(content))
	}

	// Add seeds
	f.Add(`global {
    tproxy_port: 12345
    log_level: info
}
routing {
    pname(NetworkManager) -> direct
    dip(geoip:cn) -> direct
    fallback: my_group
}
group {
    my_group {
        policy: random
    }
}`)

	f.Add(strings.TrimSpace(`
global{key:val
list: a,b, c [annotation:value1, annotation:value2]
nested { key: val }
'bare_literal'
}
routing     {
pname(NetworkManager)->direct
dip(geoip:        cn,10.0.0/8)-> direct}`))

	f.Add(strings.TrimSpace(`
routing {
    domain(
    keyword:foo, keyword:bar,
    # geosite:baz,
    geosite:qux) -> direct
    dip(geoip:cn,
    10.0.0/8) -> direct
}`))

	f.Fuzz(func(t *testing.T, data string) {
		// 1. Never panics:
		// The test runner handles panics. If this function panics, the test fails.

		// Parse original
		ast1, err1 := Parse(data)

		// Format original
		formatted1, errF1 := FormatWithIndent(data, "    ")

		// 2. Consistency (Fail/Fail or Success/Success)
		if err1 != nil {
			// If Parse fails, Format might succeed (if it's a semantic error not a syntax error),
			// but the formatted output MUST also fail to Parse.
			if errF1 == nil {
				_, err2 := Parse(formatted1)
				if err2 == nil {
					t.Errorf("Parse failed but formatted output parsed successfully.\nInput: %q\nFormatted: %q\nParse Error: %v", data, formatted1, err1)
				}
			}
			// If errF1 != nil, then both failed (or Format failed), which is consistent enough.
			return
		}

		if errF1 != nil {
			t.Errorf("Parse succeeded but Format failed.\nInput: %q\nFormat Error: %v", data, errF1)
			return
		}

		// 2b. Consistency (Same AST)
		ast2, err2 := Parse(formatted1)
		if err2 != nil {
			t.Errorf("Formatted output failed to parse.\nOriginal: %q\nFormatted: %q\nError: %v", data, formatted1, err2)
			return
		}

		if !reflect.DeepEqual(ast1, ast2) {
			t.Errorf("AST mismatch between original and formatted.\nOriginal: %q\nFormatted: %q", data, formatted1)
		}

		// 3. Orthogonality (Idempotency)
		// Formatting the formatted output should result in the exact same string.
		formatted2, errF2 := FormatWithIndent(formatted1, "    ")
		if errF2 != nil {
			t.Errorf("Second formatting pass failed: %v", errF2)
			return
		}

		if formatted1 != formatted2 {
			t.Errorf("Formatting is not idempotent.\nPass 1:\n%s\nPass 2:\n%s", formatted1, formatted2)
		}
	})
}
