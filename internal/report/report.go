// Package report builds and renders the findings produced by the spf and
// dmarc packages, as text or JSON.
package report

import (
	"github.com/mentesan/mailseck/internal/dmarc"
	"github.com/mentesan/mailseck/internal/spf"
)

// Severity is a finding's severity level. It has exactly three values,
// keeping the contract simple for both the text and JSON renderers and
// for any automation consuming the JSON output.
type Severity string

const (
	// Info marks a finding that describes expected, non-risky behavior.
	Info Severity = "info"

	// Warn marks a finding that deserves attention but is not, by
	// itself, an active spoofing risk.
	Warn Severity = "warn"

	// Crit marks a finding that represents a real spoofing exposure.
	Crit Severity = "crit"
)

// Finding is a single reported observation about a domain's SPF or
// DMARC posture.
type Finding struct {
	// Code is a short, stable machine-readable identifier for the rule
	// this finding evaluates (e.g. "spf_overlap", "dmarc_policy"). It
	// stays the same regardless of Severity, and across any future
	// wording change to Title or Detail, so automation consuming the
	// JSON output should match on Code, never on Title.
	Code string `json:"code"`

	// Severity is the finding's severity level.
	Severity Severity `json:"severity"`

	// Title is a short, human-readable summary of the finding.
	Title string `json:"title"`

	// Detail explains the finding and, where applicable, what to do
	// about it, in one or two sentences.
	Detail string `json:"detail"`

	// Items lists additional itemized detail too long or too
	// structured for Detail's sentence or two -- one line per
	// overlapping CIDR, or one hostname per unresolved host, for
	// example -- instead of folding them into one long, delimited
	// Detail string. It is always a non-nil slice, empty when a finding
	// has no items, so automation never has to special-case null.
	Items []string `json:"items"`
}

// Report is the complete result of analyzing a domain's SPF and DMARC
// posture, combining both analyses' raw results with the findings
// derived from them.
type Report struct {
	// Domain is the domain that was analyzed.
	Domain string `json:"domain"`

	// SPF is the domain's resolved and evaluated SPF record.
	SPF spf.SPFResult `json:"spf"`

	// DMARC is the domain's resolved and parsed DMARC record.
	DMARC *dmarc.DMARCResult `json:"dmarc"`

	// Findings lists every observation derived from SPF and DMARC, in
	// the order they were produced.
	Findings []Finding `json:"findings"`
}
