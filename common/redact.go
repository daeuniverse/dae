/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"regexp"
	"strings"
)

// redactedPlaceholder is what every credential-bearing URL component becomes in
// a log line.
const redactedPlaceholder = "[redacted]"

// inlineUserinfoPattern matches the authority of any scheme://user:pass@host
// form inside free text. Quotes and backslashes are allowed inside the
// authority: parser errors often print a %q-quoted link, and a password may
// itself contain a quote. Excluding those characters left the credential in
// the log whenever the text was quoted or escaped.
//
// `/`, `?` and `#` are allowed inside the matched authority even though
// RFC 3986 forbids them in a userinfo: a standard-base64 credential routinely
// contains `/`, and stopping at the first one left the password in the log.
// Over-redacting a path that happens to contain `@` is harmless; leaking a
// credential into the log is not.
var inlineUserinfoPattern = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^\s]+@`)

// inlineQueryPattern matches a query string inside free text.
var inlineQueryPattern = regexp.MustCompile(`\?[^\s"'<>]+`)

// RedactURL removes what makes a URL a credential: the userinfo and every query
// value. Scheme, host and path stay, because a log line about a subscription is
// useless without them.
//
// A share or subscription link leaks through logs whenever it is printed, and
// the two carriers are `scheme://user:pass@host` and `?token=...`. Redaction
// happens on the string rather than a parsed URL so malformed links — exactly
// the ones an error path prints — are covered too.
func RedactURL(raw string) string {
	if raw == "" {
		return raw
	}
	redacted := redactUserinfo(raw)
	if index := strings.IndexByte(redacted, '?'); index >= 0 {
		redacted = redacted[:index] + redactQuery(redacted[index:])
	}
	return redacted
}

// RedactInlineURLs redacts credentials inside free text, which is the shape a
// transport error takes: a *url.Error quotes the full request URL, so a failed
// subscription fetch would otherwise print its token.
func RedactInlineURLs(text string) string {
	if text == "" {
		return text
	}
	text = inlineUserinfoPattern.ReplaceAllString(text, "${1}"+redactedPlaceholder+"@")
	return inlineQueryPattern.ReplaceAllString(text, "?"+redactedPlaceholder)
}

// redactUserinfo rewrites the authority part of any scheme://user:pass@host form.
// It works on the raw string because url.Parse rejects the malformed links that
// error paths are most likely to print.
func redactUserinfo(raw string) string {
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 0 {
		return raw
	}
	authorityStart := schemeEnd + 3
	// RFC 3986 ends the authority at the first '/', '?' or '#'; whitespace ends
	// the URL itself. Quotes stay part of it: an escaped password may contain
	// one, and quoting the link must not hide the credential.
	authorityEnd := len(raw)
	if index := strings.IndexAny(raw[authorityStart:], "/?# \t\r\n"); index >= 0 {
		authorityEnd = authorityStart + index
	}
	at := strings.LastIndex(raw[authorityStart:authorityEnd], "@")
	if at < 0 {
		// A malformed link can carry '/', '?' or '#' inside its credential
		// (standard base64 does), so the RFC authority cut misses the '@' and
		// the credential would be returned verbatim. Fall back to the last '@'
		// before the token ends: redacting too much is harmless, leaking a
		// password is not.
		end := len(raw)
		if index := strings.IndexAny(raw[authorityStart:], " \t\r\n"); index >= 0 {
			end = authorityStart + index
		}
		at = strings.LastIndex(raw[authorityStart:end], "@")
		if at < 0 {
			return raw
		}
	}
	userinfoStart := authorityStart
	userinfoEnd := authorityStart + at
	return raw[:userinfoStart] + redactedPlaceholder + raw[userinfoEnd:]
}

// redactQuery keeps the parameter names and drops every value, so a log line
// still shows which parameters a subscription used.
func redactQuery(query string) string {
	if query == "" || query == "?" {
		return query
	}
	parts := strings.Split(query[1:], "&")
	for i, part := range parts {
		if part == "" {
			continue
		}
		key, _, found := strings.Cut(part, "=")
		if !found {
			// A bare flag carries no secret of its own; keep it as written.
			continue
		}
		parts[i] = key + "=" + redactedPlaceholder
	}
	return "?" + strings.Join(parts, "&")
}
