package spf

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
)

// maxSPFLookups is the maximum number of DNS lookups a valid SPF record
// may consume, per RFC 7208 §4.6.4. Exceeding it makes the record a
// permanent error for any compliant mail client.
const maxSPFLookups = 10

// ErrLookupLimitExceeded is returned by Analyze when a record's
// include, redirect, a, mx, ptr, and exists terms together consume more
// than maxSPFLookups DNS lookups, per RFC 7208 §4.6.4.
var ErrLookupLimitExceeded = errors.New("spf: DNS lookup limit exceeded")

// ErrCyclicReference is returned by Analyze when an include or redirect
// chain revisits a host already seen earlier in the same analysis, which
// would otherwise recurse forever.
var ErrCyclicReference = errors.New("spf: cyclic include/redirect reference")

// analyzeState carries the mutable state threaded through one Analyze
// call's recursive walk.
type analyzeState struct {
	resolver Resolver
	cidrs    map[string][]netip.Prefix
	visited  map[string]bool
	result   *SPFResult
}

// Analyze resolves domain's SPF record and walks its full include and
// redirect chain, counting DNS lookups, summing permitted addresses,
// checking them against cidrs (provider name to its public prefixes, as
// returned by cidr.Load or cidr.Cache), and recording any hostname that
// fails to resolve. It stops and returns an error the moment the chain
// would exceed the RFC 7208 lookup budget or revisit an already-seen
// host; in both cases recursion halts before making the offending DNS
// query, so it can never loop forever.
//
// A domain that publishes no SPF record at all is not an error: the
// returned SPFResult simply has an empty RawRecord.
func Analyze(ctx context.Context, resolver Resolver, domain string, cidrs map[string][]netip.Prefix) (SPFResult, error) {
	// IrresolvableHosts and Overlaps start as non-nil empty slices, not
	// nil, so they always serialize to JSON as [] rather than null --
	// automation consuming the output should never have to special-case
	// a null collection.
	result := SPFResult{IrresolvableHosts: []string{}, Overlaps: []Overlap{}}
	state := &analyzeState{
		resolver: resolver,
		cidrs:    cidrs,
		visited:  map[string]bool{domain: true},
		result:   &result,
	}

	record, found, err := state.fetchSPFRecord(ctx, domain)
	if err != nil {
		return result, fmt.Errorf("spf: resolve %s: %w", domain, err)
	}
	if !found {
		return result, nil
	}
	result.RawRecord = record

	if err := state.walkRecord(ctx, domain, record, true, false); err != nil {
		return result, err
	}

	return result, nil
}

// fetchSPFRecord resolves host's TXT records and returns the one
// beginning with "v=spf1", if any.
func (s *analyzeState) fetchSPFRecord(ctx context.Context, host string) (string, bool, error) {
	txts, err := s.resolver.LookupTXT(ctx, host)
	if err != nil {
		return "", false, err
	}
	for _, txt := range txts {
		if len(txt) >= 6 && strings.EqualFold(txt[:6], "v=spf1") {
			return txt, true, nil
		}
	}
	return "", false, nil
}

// walkRecord parses each space-separated term of record: counting DNS
// lookups, summing and overlap-checking ip4/ip6 ranges, tracking the
// "all" mechanism's qualifier when isRootChain is true, and recursing
// into include and redirect targets. host is the domain that published
// record, attached to any Overlap found here so the report can say
// which link in the chain authorized the offending range. isRootChain
// is true for the domain originally passed to Analyze and for any
// domain reached purely by following redirects from it, since a
// redirect fully replaces the record being evaluated; it is false
// inside an include, whose own "all" mechanism does not affect the
// parent record's default result. trusted is true once the chain has
// entered a known first-party mail vendor's own SPF record (see
// trustedhosts.go); it suppresses overlap findings for ip4/ip6 ranges
// found from that point on, since the vendor's own infrastructure is
// not the risk the overlap check exists to catch.
func (s *analyzeState) walkRecord(ctx context.Context, host, record string, isRootChain, trusted bool) error {
	for _, part := range strings.Fields(record) {
		if strings.EqualFold(part, "v=spf1") {
			continue
		}

		mechType, value, qualifier, err := parseMechanism(part)
		if err != nil {
			if errors.Is(err, ErrMacroNotSupported) && isLookupMechanism(mechType) {
				if err := s.chargeLookup(); err != nil {
					return err
				}
			}
			continue
		}

		switch mechType {
		case "all":
			if isRootChain {
				s.result.HasHardFail = qualifier == '-'
			}

		case "ip4", "ip6":
			s.countAndCheckOverlap(host, mechType, value, trusted)

		case "a", "mx", "ptr", "exists":
			if err := s.chargeLookup(); err != nil {
				return err
			}

		case "include":
			if err := s.chargeLookup(); err != nil {
				return err
			}
			if err := s.recurseInto(ctx, value, false, trusted); err != nil {
				return err
			}

		case "redirect":
			if err := s.chargeLookup(); err != nil {
				return err
			}
			if err := s.recurseInto(ctx, value, isRootChain, trusted); err != nil {
				return err
			}
		}
	}

	return nil
}

// recurseInto follows an include or redirect target: it guards against
// cycles, resolves the target's SPF record, and walks it. A target that
// fails to resolve is recorded in IrresolvableHosts rather than treated
// as fatal, since one broken branch of the chain should not prevent
// evaluating the rest of the record. Once trusted is true it stays true
// for everything reached from here on; if it is not yet true, it becomes
// true when host itself is a known first-party mail vendor hostname.
//
// s.visited marks host only while it is on the current recursion path
// (an ancestor), not for the whole analysis: it is unmarked via defer
// once this call returns. A cycle is a host that revisits one of its
// own ancestors; it is not the same thing as two unrelated branches of
// the include tree both happening to reference the same host, which is
// an extremely common, entirely legitimate pattern (e.g. two different
// ESPs whose own SPF records both include a third, shared provider).
// Marking a host as "seen" forever, instead of just "on the current
// path", would misreport that ordinary diamond shape as a cycle.
func (s *analyzeState) recurseInto(ctx context.Context, host string, isRootChain, trusted bool) error {
	if host == "" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.visited[host] {
		return fmt.Errorf("%w: %s", ErrCyclicReference, host)
	}
	s.visited[host] = true
	defer delete(s.visited, host)

	trusted = trusted || isTrustedMailHost(host)

	record, found, err := s.fetchSPFRecord(ctx, host)
	if err != nil {
		s.result.IrresolvableHosts = append(s.result.IrresolvableHosts, host)
		return nil
	}
	if !found {
		return nil
	}

	return s.walkRecord(ctx, host, record, isRootChain, trusted)
}

// chargeLookup accounts for one more RFC 7208 §4.6.4 DNS lookup,
// returning ErrLookupLimitExceeded the moment the budget is exceeded.
func (s *analyzeState) chargeLookup() error {
	s.result.TotalLookups++
	if s.result.TotalLookups > maxSPFLookups {
		return fmt.Errorf("%w: %d lookups", ErrLookupLimitExceeded, s.result.TotalLookups)
	}
	return nil
}

// countAndCheckOverlap parses value as an ip4 or ip6 mechanism's address
// or CIDR, adds its address count to TotalIPs, and records an Overlap for
// every cloud-provider prefix it overlaps, attributed to host (the
// domain whose own SPF record published this mechanism). A value that
// fails to parse signals a malformed record, not a condition this
// analysis needs to abort over, so it is silently skipped. When trusted
// is true (see walkRecord), the range still counts toward TotalIPs -- it
// is a real, permitted sender range -- but never produces an Overlap
// finding.
func (s *analyzeState) countAndCheckOverlap(host, mechType, value string, trusted bool) {
	prefix, err := parseIPMechanismValue(mechType, value)
	if err != nil {
		return
	}

	s.result.TotalIPs += prefixSize(prefix)

	if trusted {
		return
	}

	for provider, cloudPrefixes := range s.cidrs {
		for _, cloudPrefix := range cloudPrefixes {
			if prefix.Overlaps(cloudPrefix) {
				s.result.Overlaps = append(s.result.Overlaps, Overlap{
					Host:        host,
					SPFPrefix:   prefix,
					CloudPrefix: cloudPrefix,
					Provider:    provider,
				})
			}
		}
	}
}

// isLookupMechanism reports whether mechType is one of the terms RFC 7208
// §4.6.4 counts against the DNS lookup budget.
func isLookupMechanism(mechType string) bool {
	switch mechType {
	case "include", "a", "mx", "ptr", "exists", "redirect":
		return true
	default:
		return false
	}
}

// parseIPMechanismValue parses an ip4 or ip6 mechanism's value as a
// netip.Prefix, defaulting to a /32 or /128 host route when value carries
// no explicit prefix length, per RFC 7208 §5.6.
func parseIPMechanismValue(mechType, value string) (netip.Prefix, error) {
	if !strings.Contains(value, "/") {
		if mechType == "ip4" {
			value += "/32"
		} else {
			value += "/128"
		}
	}
	return netip.ParsePrefix(value)
}

// prefixSize returns the number of addresses covered by p, saturating at
// math.MaxUint64 for ranges too large to represent exactly (see the
// caveat on SPFResult.TotalIPs).
func prefixSize(p netip.Prefix) uint64 {
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits >= 64 {
		return math.MaxUint64
	}
	return uint64(1) << uint(hostBits)
}
