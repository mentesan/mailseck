package main

import "regexp"

// domainPattern is a simplified RFC 1035 hostname check: one or more
// dot-separated labels (letters, digits, internal hyphens, 1-63 chars,
// no leading/trailing hyphen), ending in a final label of at least two
// letters. It is deliberately not a full RFC 1035/1123 grammar, since
// its only job is to keep obviously malformed input from ever reaching
// a DNS query.
var domainPattern = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// validDomain reports whether domain looks like a syntactically valid
// hostname.
func validDomain(domain string) bool {
	return domainPattern.MatchString(domain)
}
