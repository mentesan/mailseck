package report

import (
	"strings"
	"testing"

	"github.com/mentesan/mailseck/internal/dmarc"
	"github.com/mentesan/mailseck/internal/spf"
)

func TestSuggestDMARCAbsentRecordIsPurelyAdditive(t *testing.T) {
	got := suggestDMARC("example.com", nil)
	if got == nil {
		t.Fatal("suggestDMARC() = nil, want a suggestion for a domain with no DMARC record")
	}
	if !strings.Contains(got.Record, "p=none") {
		t.Errorf("Record = %q, want p=none as the safe starting point", got.Record)
	}
	if !strings.Contains(got.Record, "rua=mailto:dmarc-reports@example.com") {
		t.Errorf("Record = %q, want a rua tag scoped to the analyzed domain", got.Record)
	}
	if got.Caveat != baselineCaveat {
		t.Errorf("Caveat = %q, want only the baseline caveat: a from-scratch p=none record changes no mail handling", got.Caveat)
	}
}

func TestSuggestDMARCWeakPolicyIsTightenedToQuarantineNotReject(t *testing.T) {
	result := &dmarc.DMARCResult{
		IsPresent: true, Policy: "none", SubdomainPolicy: "none",
		Percentage: 100, RUA: []string{"mailto:existing@example.com"},
	}
	got := suggestDMARC("example.com", result)
	if got == nil {
		t.Fatal("suggestDMARC() = nil, want a suggestion for p=none")
	}
	if !strings.Contains(got.Record, "p=quarantine") {
		t.Errorf("Record = %q, want p=quarantine as the minimal safe step, not reject", got.Record)
	}
	if strings.Contains(got.Record, "p=reject") {
		t.Errorf("Record = %q, must not jump straight to p=reject", got.Record)
	}
	if !strings.Contains(got.Caveat, tighteningCaveat) {
		t.Errorf("Caveat = %q, want the tightening warning since this changes enforcement", got.Caveat)
	}
}

func TestSuggestDMARCMissingRUAIsAddedWithoutTighteningCaveat(t *testing.T) {
	result := &dmarc.DMARCResult{
		IsPresent: true, Policy: "reject", SubdomainPolicy: "reject", Percentage: 100,
	}
	got := suggestDMARC("example.com", result)
	if got == nil {
		t.Fatal("suggestDMARC() = nil, want a suggestion to add rua even though policy is already strong")
	}
	if !strings.Contains(got.Record, "p=reject") || !strings.Contains(got.Record, "sp=reject") {
		t.Errorf("Record = %q, want the existing strong policy preserved, not weakened", got.Record)
	}
	if !strings.Contains(got.Record, "rua=mailto:dmarc-reports@example.com") {
		t.Errorf("Record = %q, want a rua tag added", got.Record)
	}
	if strings.Contains(got.Caveat, tighteningCaveat) {
		t.Errorf("Caveat = %q, adding rua is purely additive and must not carry the tightening warning", got.Caveat)
	}
}

func TestSuggestDMARCHealthyRecordNeedsNoSuggestion(t *testing.T) {
	result := &dmarc.DMARCResult{
		IsPresent: true, Policy: "reject", SubdomainPolicy: "reject",
		Percentage: 100, RUA: []string{"mailto:reports@example.com"},
	}
	if got := suggestDMARC("example.com", result); got != nil {
		t.Errorf("suggestDMARC() = %+v, want nil: this record already meets the safe minimum", got)
	}
}

func TestSuggestDMARCPreservesStrongerExplicitSubdomainPolicy(t *testing.T) {
	// p=none is weak and gets tightened, but sp=reject is already
	// stronger than the new p=quarantine and must not be downgraded to
	// match it.
	result := &dmarc.DMARCResult{
		IsPresent: true, Policy: "none", SubdomainPolicy: "reject",
		Percentage: 100, RUA: []string{"mailto:existing@example.com"},
	}
	got := suggestDMARC("example.com", result)
	if got == nil {
		t.Fatal("suggestDMARC() = nil, want a suggestion since p=none is weak")
	}
	if !strings.Contains(got.Record, "sp=reject") {
		t.Errorf("Record = %q, want the existing, stronger sp=reject preserved", got.Record)
	}
}

func TestSuggestDMARCLowPercentageIsRaisedTo100(t *testing.T) {
	result := &dmarc.DMARCResult{
		IsPresent: true, Policy: "quarantine", SubdomainPolicy: "quarantine",
		Percentage: 50, RUA: []string{"mailto:existing@example.com"},
	}
	got := suggestDMARC("example.com", result)
	if got == nil {
		t.Fatal("suggestDMARC() = nil, want a suggestion for pct=50")
	}
	if !strings.Contains(got.Record, "pct=100") {
		t.Errorf("Record = %q, want pct raised to 100", got.Record)
	}
	if !strings.Contains(got.Caveat, tighteningCaveat) {
		t.Errorf("Caveat = %q, want the tightening warning since this expands enforcement coverage", got.Caveat)
	}
}

func TestBuildAttachesDMARCSuggestionToReport(t *testing.T) {
	report := Build("example.com", spf.SPFResult{}, nil)
	if report.DMARCSuggestion == nil {
		t.Fatal("Build() Report.DMARCSuggestion = nil, want a suggestion when there is no DMARC record")
	}
}

func TestBuildOmitsDMARCSuggestionWhenAlreadyHealthy(t *testing.T) {
	dmarcResult := &dmarc.DMARCResult{
		IsPresent: true, Policy: "reject", SubdomainPolicy: "reject",
		Percentage: 100, RUA: []string{"mailto:reports@example.com"},
	}
	report := Build("example.com", spf.SPFResult{}, dmarcResult)
	if report.DMARCSuggestion != nil {
		t.Errorf("Report.DMARCSuggestion = %+v, want nil for an already-healthy record", report.DMARCSuggestion)
	}
}
