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

type simpleInterfaceMather struct {
	pattern string
}

func (m *simpleInterfaceMather) Match(ifname string) bool {
	return m.pattern == ifname
}

type wildcardInterfaceMather struct {
	pattern string
	re      *regexp.Regexp
}

func (m *wildcardInterfaceMather) Match(ifname string) bool {
	return m.pattern == ifname || m.re.MatchString(ifname)
}

func NewInterfaceMather(pattern string) (InterfaceMather, error) {
	if !IsInterfaceNameIsWildcard(pattern) {
		return &simpleInterfaceMather{pattern}, nil
	}

	return newWildcardInterfaceMather(pattern)
}

func newWildcardInterfaceMather(pattern string) (*wildcardInterfaceMather, error) {
	regexPattern := "^" +
		strings.ReplaceAll(
			strings.ReplaceAll(pattern, "*", ".*"),
			"+", ".+") +
		"$"

	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to create interface matcher for ifname pattern %s: %w", pattern, err)
	}
	return &wildcardInterfaceMather{pattern, regex}, nil
}
