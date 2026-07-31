package report

import (
	"fmt"
	"strings"

	"github.com/mentesan/mailseck/internal/dmarc"
)

// baselineCaveat is always present on a DMARCSuggestion: it is a
// suggested minimum, not a directive, since this tool has no visibility
// into which senders are actually SPF/DKIM-aligned for this domain.
const baselineCaveat = "This is a suggested minimum configuration, not a directive -- " +
	"confirm with whoever owns email security for this domain before publishing it."

// tighteningCaveat is appended to baselineCaveat whenever suggestDMARC
// recommends a stricter p, sp, or pct than the domain currently
// publishes, since that specifically risks breaking legitimate mail if
// some sending source isn't aligned yet.
const tighteningCaveat = " This suggestion also tightens enforcement: confirm every legitimate " +
	"sending source (including any third-party service) is SPF- or DKIM-aligned before publishing it, " +
	"or legitimate mail may be quarantined or rejected."

// DMARCSuggestion is a minimal next-step DMARC record report.Build
// recommends when the domain's current record (or its absence) falls
// short of a safe minimum. It is nil when the current record already
// meets that bar, so there is nothing to suggest.
type DMARCSuggestion struct {
	// Record is the suggested full DMARC TXT record value.
	Record string `json:"record"`

	// Caveat always explains that this is a suggestion to review, not a
	// directive; it also warns specifically about enforcement risk
	// whenever the suggestion tightens p, sp, or pct rather than only
	// adding visibility (e.g. a missing rua).
	Caveat string `json:"caveat"`
}

// suggestDMARC proposes a minimal, safer DMARC record for domain, based
// on result. A completely absent record gets the standard, purely
// additive starting point (p=none plus aggregate reporting): safe by
// construction, since it changes no mail handling at all. An existing
// but weak record (p=none, pct<100, or an effectively-none subdomain
// policy) gets the smallest tightening step this package considers
// reasonable to suggest -- quarantine rather than an outright jump to
// reject -- since jumping straight to reject without knowing whether
// every legitimate sender is aligned can silently break mail delivery.
// A record that already meets this bar gets no suggestion at all.
func suggestDMARC(domain string, result *dmarc.DMARCResult) *DMARCSuggestion {
	if result == nil || !result.IsPresent {
		return &DMARCSuggestion{
			Record: fmt.Sprintf("v=DMARC1; p=none; rua=mailto:dmarc-reports@%s", domain),
			Caveat: baselineCaveat,
		}
	}

	policy := result.Policy
	subdomainPolicy := result.SubdomainPolicy
	if subdomainPolicy == "" {
		subdomainPolicy = result.EffectiveSubdomainPolicy()
	}
	pct := result.Percentage
	rua := result.RUA

	tightened := false

	if policy == "none" {
		policy = "quarantine"
		tightened = true
	}
	if result.EffectiveSubdomainPolicy() == "none" {
		subdomainPolicy = policy
		tightened = true
	}
	if pct < 100 {
		pct = 100
		tightened = true
	}

	addedRUA := false
	if len(rua) == 0 {
		rua = []string{"mailto:dmarc-reports@" + domain}
		addedRUA = true
	}

	if !tightened && !addedRUA {
		return nil
	}

	record := fmt.Sprintf("v=DMARC1; p=%s; sp=%s; pct=%d; rua=%s",
		policy, subdomainPolicy, pct, strings.Join(rua, ","))

	caveat := baselineCaveat
	if tightened {
		caveat += tighteningCaveat
	}

	return &DMARCSuggestion{Record: record, Caveat: caveat}
}
