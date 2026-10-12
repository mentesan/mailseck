// Package dmarc resolves and evaluates DMARC records to detect weak or
// absent domain-level email authentication policies.
package dmarc

import "github.com/mentesan/mailseck/internal/lookup"

// DMARCResult is the outcome of resolving and parsing a domain's DMARC
// record.
type DMARCResult struct {
	// IsPresent reports whether the domain publishes a single, valid
	// DMARC TXT record. It is always equal to Status == lookup.Found.
	IsPresent bool `json:"is_present"`

	// Status is the outcome of the _dmarc.<domain> TXT lookup:
	// lookup.Found for exactly one "v=DMARC1" record, lookup.NotFound
	// when the name does not exist, has no TXT record, or has zero or
	// more than one candidate record (invalid per RFC 7489 §6.6.3), and
	// lookup.Error when the lookup failed and nothing is known. With any
	// status other than lookup.Found, RawRecord is empty and every tag
	// field is left at its empty value.
	Status lookup.Status `json:"status"`

	// Error is the lookup's error message when Status is lookup.Error,
	// and empty otherwise.
	Error string `json:"error"`

	// RawRecord is the matched DMARC TXT record, as published.
	RawRecord string `json:"raw_record"`

	// Policy is the literal value of the "p" tag (e.g. "reject",
	// "quarantine", or "none").
	Policy string `json:"policy"`

	// SubdomainPolicy is the literal value of the "sp" tag, or empty if
	// the tag is absent. Per RFC 7489, an absent "sp" means subdomains
	// inherit Policy; this field reports only what was actually
	// published, leaving that inheritance decision to the caller.
	SubdomainPolicy string `json:"subdomain_policy"`

	// Percentage is the value of the "pct" tag: the percentage of
	// messages subjected to the policy. It defaults to 100, per RFC
	// 7489 §6.3, when the tag is absent or unparseable.
	Percentage int `json:"percentage"`

	// RUA lists the aggregate report URIs from the "rua" tag, in the
	// order published.
	RUA []string `json:"rua"`

	// RUF lists the forensic report URIs from the "ruf" tag, in the
	// order published.
	RUF []string `json:"ruf"`
}

// EffectiveSubdomainPolicy returns the policy that actually applies to
// subdomains: SubdomainPolicy if the domain published an "sp" tag, or
// Policy otherwise, per RFC 7489 §6.3's inheritance rule. Use this
// instead of reading SubdomainPolicy directly whenever the question is
// "what happens to mail from a subdomain", rather than "what did this
// domain literally publish".
func (r *DMARCResult) EffectiveSubdomainPolicy() string {
	if r.SubdomainPolicy != "" {
		return r.SubdomainPolicy
	}
	return r.Policy
}
