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
	// Severity is the finding's severity level.
	Severity Severity `json:"severity"`

	// Title is a short, human-readable summary of the finding.
	Title string `json:"title"`

	// Detail explains the finding and, where applicable, what to do
	// about it.
	Detail string `json:"detail"`
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
