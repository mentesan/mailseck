// Package dmarc resolves and evaluates DMARC records to detect weak or
// absent domain-level email authentication policies.
package dmarc

// DMARCResult is the outcome of resolving and parsing a domain's DMARC
// record.
type DMARCResult struct {
	// IsPresent reports whether the domain publishes a single, valid
	// DMARC TXT record. It is false both when _dmarc.<domain> has no
	// matching record and when the DNS lookup itself failed, since the
	// overwhelming majority of domains signal "no DMARC" precisely by
	// not publishing that subdomain at all.
	IsPresent bool

	// RawRecord is the matched DMARC TXT record, as published.
	RawRecord string

	// Policy is the literal value of the "p" tag (e.g. "reject",
	// "quarantine", or "none").
	Policy string

	// SubdomainPolicy is the literal value of the "sp" tag, or empty if
	// the tag is absent. Per RFC 7489, an absent "sp" means subdomains
	// inherit Policy; this field reports only what was actually
	// published, leaving that inheritance decision to the caller.
	SubdomainPolicy string

	// Percentage is the value of the "pct" tag: the percentage of
	// messages subjected to the policy. It defaults to 100, per RFC
	// 7489 §6.3, when the tag is absent or unparseable.
	Percentage int

	// RUA lists the aggregate report URIs from the "rua" tag, in the
	// order published.
	RUA []string

	// RUF lists the forensic report URIs from the "ruf" tag, in the
	// order published.
	RUF []string
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
