// Package spf resolves and evaluates SPF records to detect email spoofing
// conditions, following the recursion and lookup-counting rules of RFC 7208.
package spf

import (
	"context"
	"net/netip"
)

// Resolver abstracts the DNS lookups Analyze needs, letting tests inject a
// fake implementation instead of querying real DNS.
type Resolver interface {
	// LookupTXT returns the TXT records published for host.
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

// Overlap records an SPF-permitted CIDR that overlaps a publicly-rentable
// cloud provider CIDR, meaning a third party could obtain that IP and send
// mail the SPF record would treat as authorized.
type Overlap struct {
	// SPFPrefix is the CIDR taken from the SPF record.
	SPFPrefix netip.Prefix `json:"spf_prefix"`

	// CloudPrefix is the overlapping CIDR taken from the cloud
	// provider's published range.
	CloudPrefix netip.Prefix `json:"cloud_prefix"`

	// Provider is the cloud provider's identifier, e.g. "AWS" or "GCP".
	Provider string `json:"provider"`
}

// SPFResult is the outcome of resolving and evaluating a domain's SPF
// record, including its full include/redirect chain.
type SPFResult struct {
	// RawRecord is the domain's top-level SPF TXT record, as published.
	RawRecord string `json:"raw_record"`

	// TotalIPs is the number of IPv4 and IPv6 addresses the record
	// permits as senders. Note: a pathological ip6 mechanism with a very
	// short prefix length can exceed the range of uint64; that edge case
	// is intentionally left unhandled in this field's type for v1.0.
	TotalIPs uint64 `json:"total_ips"`

	// TotalLookups is the number of DNS lookups the record consumed
	// while resolving include, redirect, a, mx, ptr and exists
	// mechanisms, per RFC 7208 §4.6.4. A value above 10 makes the
	// record invalid for most mail clients.
	TotalLookups int `json:"total_lookups"`

	// HasHardFail reports whether the record's "all" mechanism uses the
	// "-" qualifier, instructing clients to reject non-matching senders
	// outright.
	HasHardFail bool `json:"has_hard_fail"`

	// IrresolvableHosts lists every hostname encountered during
	// recursion whose DNS lookup failed, in the order they were found.
	IrresolvableHosts []string `json:"irresolvable_hosts"`

	// Overlaps lists every SPF-permitted CIDR found to overlap a
	// publicly-rentable cloud provider range.
	Overlaps []Overlap `json:"overlaps"`
}
