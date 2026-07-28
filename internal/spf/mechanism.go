package spf

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnknownMechanism is returned by parseMechanism when a term's type is
// not one of the SPF mechanisms from RFC 7208 §5, nor the "redirect"
// modifier this package follows the same way it follows "include".
var ErrUnknownMechanism = errors.New("spf: unknown mechanism")

// ErrMacroNotSupported is returned by parseMechanism when a term uses SPF
// macro expansion syntax ("%{...}"), which this package does not
// evaluate. Such a term is reported rather than silently skipped or
// guessed at.
var ErrMacroNotSupported = errors.New("spf: macro expansion not supported")

// errEmptyMechanism is returned by parseMechanism when there is no
// mechanism left to parse, either because part itself is empty or
// because it was only a bare qualifier.
var errEmptyMechanism = errors.New("spf: empty mechanism")

// knownMechanisms are the SPF mechanism names from RFC 7208 §5, plus the
// "redirect" modifier.
var knownMechanisms = map[string]bool{
	"all":      true,
	"include":  true,
	"a":        true,
	"mx":       true,
	"ptr":      true,
	"ip4":      true,
	"ip6":      true,
	"exists":   true,
	"redirect": true,
}

// parseMechanism splits a single space-separated term of an SPF record
// into its qualifier ('+', '-', '~', or '?', defaulting to '+' when
// omitted), its mechanism type (lowercased, e.g. "include" or "ip4"), and
// its value: the text after the ":" or "=" separator, or after the type
// name itself for a bare cidr-length such as "a/24".
//
// It returns ErrUnknownMechanism if the type is not recognized, and
// ErrMacroNotSupported if the term uses SPF macro syntax, since this
// package does not evaluate macros. In the macro case, mechType is still
// populated (value is not), so a caller that only needs to know whether
// the term would have consumed an RFC 7208 DNS lookup can still tell.
func parseMechanism(part string) (mechType, value string, qualifier byte, err error) {
	if part == "" {
		return "", "", 0, errEmptyMechanism
	}

	qualifier = '+'
	rest := part
	switch part[0] {
	case '+', '-', '~', '?':
		qualifier = part[0]
		rest = part[1:]
	}

	if rest == "" {
		return "", "", 0, fmt.Errorf("%w: %q", errEmptyMechanism, part)
	}

	mechType = rest
	if i := strings.IndexAny(rest, ":=/"); i >= 0 {
		mechType = rest[:i]
		if rest[i] == '/' {
			value = rest[i:]
		} else {
			value = rest[i+1:]
		}
	}
	mechType = strings.ToLower(mechType)

	if strings.Contains(rest, "%{") {
		return mechType, "", 0, fmt.Errorf("%w: %q", ErrMacroNotSupported, part)
	}

	if !knownMechanisms[mechType] {
		return "", "", 0, fmt.Errorf("%w: %q", ErrUnknownMechanism, part)
	}

	return mechType, value, qualifier, nil
}
