package report

import (
	"fmt"

	"github.com/mentesan/mailseck/internal/dmarc"
	"github.com/mentesan/mailseck/internal/spf"
)

// criticalIPThreshold and warnIPThreshold are the SPF permitted-sender
// count tiers a domain's total permitted IPs are compared against.
const (
	criticalIPThreshold = 1_000_000
	warnIPThreshold     = 10_000
)

// maxValidLookups is the RFC 7208 §4.6.4 DNS lookup budget; exceeding it
// makes an SPF record invalid for most mail clients.
const maxValidLookups = 10

// Build derives a Report's Findings from a domain's already-resolved SPF
// and DMARC results.
func Build(domain string, spfResult spf.SPFResult, dmarcResult *dmarc.DMARCResult) Report {
	var findings []Finding
	findings = append(findings, spfFindings(spfResult)...)
	findings = append(findings, dmarcFindings(dmarcResult)...)

	return Report{
		Domain:   domain,
		SPF:      spfResult,
		DMARC:    dmarcResult,
		Findings: findings,
	}
}

// spfFindings evaluates a domain's SPF result against the PRD's report
// rules. A domain with no SPF record at all gets a single Crit finding;
// every other rule only applies once a record is known to exist.
func spfFindings(result spf.SPFResult) []Finding {
	if result.RawRecord == "" {
		return []Finding{{
			Severity: Crit,
			Title:    "No SPF record is defined",
			Detail: "Mail can be easily spoofed for this domain. Either implement a record, or " +
				"explicitly set a no-send record for domains not designed to send mail: 'v=spf1 -all'.",
		}}
	}

	findings := []Finding{{
		Severity: Info,
		Title:    "SPF record is defined",
		Detail:   "Spoofed mail is somewhat prevented.",
	}}

	if result.TotalIPs > 0 {
		findings = append(findings, ipCountFinding(result.TotalIPs))
	}

	findings = append(findings, lookupCountFinding(result.TotalLookups))

	if len(result.IrresolvableHosts) > 0 {
		findings = append(findings, Finding{
			Severity: Crit,
			Title:    "A hostname could not be resolved",
			Detail: fmt.Sprintf("The entire SPF record may be ignored by clients. Unresolved: %v.",
				result.IrresolvableHosts),
		})
	} else {
		findings = append(findings, Finding{
			Severity: Info,
			Title:    "All hostnames were resolved",
			Detail:   "An irresolvable hostname may invalidate the entire record.",
		})
	}

	if result.HasHardFail {
		findings = append(findings, Finding{
			Severity: Info,
			Title:    "'-all' directive is in use",
			Detail:   "Mail clients know to hard fail spoofed mail.",
		})
	} else {
		findings = append(findings, Finding{
			Severity: Warn,
			Title:    "Directive leaves action ambiguous",
			Detail:   "Without a hard fail '-all' directive, mail clients will not take firm actions against spoofed mail.",
		})
	}

	if len(result.Overlaps) > 0 {
		findings = append(findings, overlapFinding(result.Overlaps))
	} else {
		findings = append(findings, Finding{
			Severity: Info,
			Title:    "No common public-obtainable IP ranges exist",
			Detail:   "No cloud provider IP ranges that would allow adversaries to bypass SPF are present in the record.",
		})
	}

	return findings
}

// ipCountFinding tiers a domain's total permitted SPF senders: above
// criticalIPThreshold is Crit, above warnIPThreshold is Warn, otherwise
// Info. It is only called when totalIPs > 0.
func ipCountFinding(totalIPs uint64) Finding {
	title := fmt.Sprintf("%d IPs are permitted senders", totalIPs)
	detail := "Regularly review your SPF record to ensure the record is as least-permissive as possible."

	switch {
	case totalIPs > criticalIPThreshold:
		return Finding{Severity: Crit, Title: title, Detail: detail}
	case totalIPs > warnIPThreshold:
		return Finding{Severity: Warn, Title: title, Detail: detail}
	default:
		return Finding{Severity: Info, Title: title, Detail: detail}
	}
}

// lookupCountFinding flags an SPF record that consumed more DNS lookups
// than RFC 7208 §4.6.4 permits.
func lookupCountFinding(totalLookups int) Finding {
	if totalLookups > maxValidLookups {
		return Finding{
			Severity: Crit,
			Title:    fmt.Sprintf("%d DNS lookups were made", totalLookups),
			Detail:   "Most clients refuse and ignore SPF records that result in more than 10 DNS lookups.",
		}
	}
	return Finding{
		Severity: Info,
		Title:    fmt.Sprintf("%d DNS lookup(s) were made", totalLookups),
		Detail:   "More than 10, and the record would be invalid.",
	}
}

// overlapFinding reports every SPF-permitted CIDR found to overlap a
// publicly-rentable cloud provider range. It is only called when
// overlaps is non-empty.
func overlapFinding(overlaps []spf.Overlap) Finding {
	detail := "This record contains CIDR ranges for IPs adversaries can obtain, allowing them to " +
		"bypass SPF and spoof email for your domain:"
	for _, overlap := range overlaps {
		detail += fmt.Sprintf(" %s overlaps %s (%s);", overlap.SPFPrefix, overlap.CloudPrefix, overlap.Provider)
	}

	return Finding{
		Severity: Crit,
		Title:    "Permitted ranges are public-obtainable",
		Detail:   detail,
	}
}

// dmarcFindings evaluates a domain's DMARC result against the PRD's
// report rules. A domain with no DMARC record gets a single Crit
// finding; every other rule only applies once a record is known to
// exist.
func dmarcFindings(result *dmarc.DMARCResult) []Finding {
	if result == nil || !result.IsPresent {
		return []Finding{{
			Severity: Crit,
			Title:    "No DMARC record is defined",
			Detail:   "This can leave the SPF policy ambiguous.",
		}}
	}

	findings := []Finding{{
		Severity: Info,
		Title:    "DMARC record is defined",
		Detail:   "SPF policy is less ambiguous.",
	}}

	if result.Percentage < 100 {
		findings = append(findings, Finding{
			Severity: Crit,
			Title:    fmt.Sprintf("Only %d%% of email is covered by DMARC", result.Percentage),
			Detail:   fmt.Sprintf("Email can be spoofed %d%% of the time.", 100-result.Percentage),
		})
	} else {
		findings = append(findings, Finding{
			Severity: Info,
			Title:    "100% of email is covered",
			Detail:   "The policy is not in a phased rollout.",
		})
	}

	if result.Policy == "none" {
		findings = append(findings, Finding{
			Severity: Crit,
			Title:    "DMARC policy is not active",
			Detail:   "'p=none' is the equivalent of having no DMARC record, allowing spoofed mail.",
		})
	} else {
		findings = append(findings, Finding{
			Severity: Info,
			Title:    "DMARC policy is active",
			Detail:   "A rejection criteria is in use or implied.",
		})
	}

	if result.EffectiveSubdomainPolicy() == "none" {
		detail := "'sp=none' is the equivalent of having no DMARC record for subdomains, allowing spoofed mail."
		if result.SubdomainPolicy == "" {
			detail = "No 'sp' tag is published, so subdomains inherit 'p=none' (RFC 7489 §6.3), " +
				"which is the equivalent of having no DMARC record for subdomains, allowing spoofed mail."
		}
		findings = append(findings, Finding{
			Severity: Crit,
			Title:    "DMARC policy is not active for subdomains",
			Detail:   detail,
		})
	} else {
		findings = append(findings, Finding{
			Severity: Info,
			Title:    "DMARC policy is active for subdomains",
			Detail:   "A rejection criteria is in use or implied.",
		})
	}

	return findings
}
