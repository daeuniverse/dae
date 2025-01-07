package netutils

import (
	"fmt"
	"regexp"
	"strings"
)

func IsInterfaceNameIsWildcard(ifname string) bool {
	return strings.ContainsAny(ifname, "*+")
}

type InterfaceMather interface {
	Match(ifname string) bool
}

type simpleInterfaceMatcher struct {
	pattern string
}

func (m *simpleInterfaceMatcher) Match(ifname string) bool {
	return m.pattern == ifname
}

type wildcardInterfaceMatcher struct {
	pattern string
	re      *regexp.Regexp
}

func (m *wildcardInterfaceMatcher) Match(ifname string) bool {
	return m.pattern == ifname || m.re.MatchString(ifname)
}

func NewInterfaceMatcher(pattern string) (InterfaceMather, error) {
	if !IsInterfaceNameIsWildcard(pattern) {
		return &simpleInterfaceMatcher{pattern}, nil
	}

	return newWildcardInterfaceMatcher(pattern)
}

func newWildcardInterfaceMatcher(pattern string) (*wildcardInterfaceMatcher, error) {
	regexPattern := "^" +
		strings.ReplaceAll(
			strings.ReplaceAll(pattern, "*", ".*"),
			"+", ".+") +
		"$"

	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to create interface matcher for ifname pattern %s: %w", pattern, err)
	}
	return &wildcardInterfaceMatcher{pattern, regex}, nil
}
