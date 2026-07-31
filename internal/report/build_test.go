package report

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/mentesan/mailseck/internal/dmarc"
	"github.com/mentesan/mailseck/internal/spf"
)

// findByTitle returns the first finding with the given title, for tests
// that only care about one rule at a time.
func findByTitle(findings []Finding, title string) (Finding, bool) {
	for _, f := range findings {
		if f.Title == title {
			return f, true
		}
	}
	return Finding{}, false
}

func TestBuildNoSPFRecordIsCritAndSuppressesOtherSPFFindings(t *testing.T) {
	report := Build("example.com", spf.SPFResult{}, nil)

	f, ok := findByTitle(report.Findings, "No SPF record is defined")
	if !ok || f.Severity != Crit {
		t.Fatalf("expected a Crit 'No SPF record is defined' finding, got %+v", report.Findings)
	}

	if _, ok := findByTitle(report.Findings, "SPF record is defined"); ok {
		t.Error("did not expect an 'SPF record is defined' finding when RawRecord is empty")
	}
}

func TestBuildSPFPresentWithZeroIPsSkipsIPCountFinding(t *testing.T) {
	result := spf.SPFResult{RawRecord: "v=spf1 include:other.com -all", HasHardFail: true}
	report := Build("example.com", result, nil)

	for _, f := range report.Findings {
		if f.Title == "0 IPs are permitted senders" {
			t.Errorf("did not expect an IP-count finding when TotalIPs is 0, got %+v", f)
		}
	}
}

func TestBuildIPCountCritical(t *testing.T) {
	result := spf.SPFResult{RawRecord: "v=spf1 -all", TotalIPs: 1_000_001}
	report := Build("example.com", result, nil)

	f, ok := findByTitle(report.Findings, "1000001 IPs are permitted senders")
	if !ok || f.Severity != Crit {
		t.Fatalf("expected a Crit IP-count finding, got %+v", report.Findings)
	}
}

func TestBuildIPCountWarn(t *testing.T) {
	result := spf.SPFResult{RawRecord: "v=spf1 -all", TotalIPs: 10_001}
	report := Build("example.com", result, nil)

	f, ok := findByTitle(report.Findings, "10001 IPs are permitted senders")
	if !ok || f.Severity != Warn {
		t.Fatalf("expected a Warn IP-count finding, got %+v", report.Findings)
	}
}

func TestBuildIPCountInfo(t *testing.T) {
	result := spf.SPFResult{RawRecord: "v=spf1 -all", TotalIPs: 500}
	report := Build("example.com", result, nil)

	f, ok := findByTitle(report.Findings, "500 IPs are permitted senders")
	if !ok || f.Severity != Info {
		t.Fatalf("expected an Info IP-count finding, got %+v", report.Findings)
	}
}

func TestBuildLookupsExceedingLimitIsCrit(t *testing.T) {
	result := spf.SPFResult{RawRecord: "v=spf1 -all", TotalLookups: 11}
	report := Build("example.com", result, nil)

	f, ok := findByTitle(report.Findings, "11 DNS lookups were made")
	if !ok || f.Severity != Crit {
		t.Fatalf("expected a Crit lookups finding, got %+v", report.Findings)
	}
}

func TestBuildLookupsWithinLimitIsInfo(t *testing.T) {
	result := spf.SPFResult{RawRecord: "v=spf1 -all", TotalLookups: 5}
	report := Build("example.com", result, nil)

	f, ok := findByTitle(report.Findings, "5 DNS lookup(s) were made")
	if !ok || f.Severity != Info {
		t.Fatalf("expected an Info lookups finding, got %+v", report.Findings)
	}
}

func TestBuildHardFailPresentIsInfo(t *testing.T) {
	result := spf.SPFResult{RawRecord: "v=spf1 -all", HasHardFail: true}
	report := Build("example.com", result, nil)

	f, ok := findByTitle(report.Findings, "'-all' directive is in use")
	if !ok || f.Severity != Info {
		t.Fatalf("expected an Info hard-fail finding, got %+v", report.Findings)
	}
}

func TestBuildHardFailAbsentIsWarn(t *testing.T) {
	result := spf.SPFResult{RawRecord: "v=spf1 ~all", HasHardFail: false}
	report := Build("example.com", result, nil)

	f, ok := findByTitle(report.Findings, "Directive leaves action ambiguous")
	if !ok || f.Severity != Warn {
		t.Fatalf("expected a Warn ambiguous-directive finding, got %+v", report.Findings)
	}
}

func TestBuildIrresolvableHostIsCrit(t *testing.T) {
	result := spf.SPFResult{
		RawRecord:         "v=spf1 include:broken.example -all",
		IrresolvableHosts: []string{"broken.example"},
	}
	report := Build("example.com", result, nil)

	f, ok := findByTitle(report.Findings, "A hostname could not be resolved")
	if !ok || f.Severity != Crit {
		t.Fatalf("expected a Crit irresolvable-host finding, got %+v", report.Findings)
	}
	if len(f.Items) != 1 || f.Items[0] != "broken.example" {
		t.Errorf("Items = %v, want [broken.example]: the hostname list should be structured, not folded into Detail", f.Items)
	}
}

func TestBuildAllHostsResolvedIsInfo(t *testing.T) {
	result := spf.SPFResult{RawRecord: "v=spf1 -all"}
	report := Build("example.com", result, nil)

	f, ok := findByTitle(report.Findings, "All hostnames were resolved")
	if !ok || f.Severity != Info {
		t.Fatalf("expected an Info all-hosts-resolved finding, got %+v", report.Findings)
	}
}

func TestBuildOverlapIsCrit(t *testing.T) {
	result := spf.SPFResult{
		RawRecord: "v=spf1 ip4:203.0.113.0/24 -all",
		Overlaps: []spf.Overlap{
			{Provider: "AWS"},
		},
	}
	report := Build("example.com", result, nil)

	f, ok := findByTitle(report.Findings, "Permitted ranges are public-obtainable")
	if !ok || f.Severity != Crit {
		t.Fatalf("expected a Crit overlap finding, got %+v", report.Findings)
	}
}

// TestBuildOverlapDetailStaysShortAndItemsCarryTheList guards against the
// overlap finding turning back into one long, semicolon-joined Detail
// string: with several overlaps, Detail must stay a short summary and
// each overlap must appear as its own entry in Items instead.
func TestBuildOverlapDetailStaysShortAndItemsCarryTheList(t *testing.T) {
	result := spf.SPFResult{
		RawRecord: "v=spf1 ip4:203.0.113.0/24 ip4:198.51.100.0/24 -all",
		Overlaps: []spf.Overlap{
			{Host: "example.com", SPFPrefix: netip.MustParsePrefix("203.0.113.0/24"),
				CloudPrefix: netip.MustParsePrefix("203.0.113.0/25"), Provider: "AWS"},
			{Host: "vendor.example", SPFPrefix: netip.MustParsePrefix("198.51.100.0/24"),
				CloudPrefix: netip.MustParsePrefix("198.51.100.0/25"), Provider: "GCP"},
		},
	}
	report := Build("example.com", result, nil)

	f, ok := findByTitle(report.Findings, "Permitted ranges are public-obtainable")
	if !ok {
		t.Fatalf("expected an overlap finding, got %+v", report.Findings)
	}
	if len(f.Detail) > 200 {
		t.Errorf("Detail is %d chars, want a short summary, not one entry per overlap: %q", len(f.Detail), f.Detail)
	}
	if len(f.Items) != 2 {
		t.Fatalf("Items = %v, want 2 entries, one per overlap", f.Items)
	}
	if !strings.Contains(f.Items[0], "example.com") || !strings.Contains(f.Items[1], "vendor.example") {
		t.Errorf("Items = %v, want each overlap's own Host named in its own item", f.Items)
	}
}

func TestBuildNoOverlapIsInfo(t *testing.T) {
	result := spf.SPFResult{RawRecord: "v=spf1 ip4:203.0.113.0/24 -all"}
	report := Build("example.com", result, nil)

	f, ok := findByTitle(report.Findings, "No common public-obtainable IP ranges exist")
	if !ok || f.Severity != Info {
		t.Fatalf("expected an Info no-overlap finding, got %+v", report.Findings)
	}
}

func TestBuildNoDMARCRecordIsCritAndSuppressesOtherDMARCFindings(t *testing.T) {
	report := Build("example.com", spf.SPFResult{}, nil)

	f, ok := findByTitle(report.Findings, "No DMARC record is defined")
	if !ok || f.Severity != Crit {
		t.Fatalf("expected a Crit 'No DMARC record is defined' finding, got %+v", report.Findings)
	}

	if _, ok := findByTitle(report.Findings, "DMARC record is defined"); ok {
		t.Error("did not expect a 'DMARC record is defined' finding when DMARC is absent")
	}
}

func TestBuildDMARCNotPresentIsCritEvenWithNonNilResult(t *testing.T) {
	report := Build("example.com", spf.SPFResult{}, &dmarc.DMARCResult{IsPresent: false})

	f, ok := findByTitle(report.Findings, "No DMARC record is defined")
	if !ok || f.Severity != Crit {
		t.Fatalf("expected a Crit 'No DMARC record is defined' finding, got %+v", report.Findings)
	}
}

func TestBuildDMARCFullCoverageIsInfo(t *testing.T) {
	result := &dmarc.DMARCResult{IsPresent: true, Policy: "reject", SubdomainPolicy: "reject", Percentage: 100}
	report := Build("example.com", spf.SPFResult{}, result)

	f, ok := findByTitle(report.Findings, "100% of email is covered")
	if !ok || f.Severity != Info {
		t.Fatalf("expected an Info full-coverage finding, got %+v", report.Findings)
	}
}

func TestBuildDMARCPercentageBelow100IsCrit(t *testing.T) {
	result := &dmarc.DMARCResult{IsPresent: true, Policy: "reject", SubdomainPolicy: "reject", Percentage: 50}
	report := Build("example.com", spf.SPFResult{}, result)

	f, ok := findByTitle(report.Findings, "Only 50% of email is covered by DMARC")
	if !ok || f.Severity != Crit {
		t.Fatalf("expected a Crit pct finding, got %+v", report.Findings)
	}
}

func TestBuildDMARCPolicyActiveIsInfo(t *testing.T) {
	result := &dmarc.DMARCResult{IsPresent: true, Policy: "reject", SubdomainPolicy: "reject", Percentage: 100}
	report := Build("example.com", spf.SPFResult{}, result)

	f, ok := findByTitle(report.Findings, "DMARC policy is active")
	if !ok || f.Severity != Info {
		t.Fatalf("expected an Info policy-active finding, got %+v", report.Findings)
	}
}

func TestBuildDMARCPolicyNoneIsCrit(t *testing.T) {
	result := &dmarc.DMARCResult{IsPresent: true, Policy: "none", SubdomainPolicy: "reject", Percentage: 100}
	report := Build("example.com", spf.SPFResult{}, result)

	f, ok := findByTitle(report.Findings, "DMARC policy is not active")
	if !ok || f.Severity != Crit {
		t.Fatalf("expected a Crit p=none finding, got %+v", report.Findings)
	}
}

func TestBuildDMARCSubdomainPolicyActiveIsInfo(t *testing.T) {
	result := &dmarc.DMARCResult{IsPresent: true, Policy: "reject", SubdomainPolicy: "reject", Percentage: 100}
	report := Build("example.com", spf.SPFResult{}, result)

	f, ok := findByTitle(report.Findings, "DMARC policy is active for subdomains")
	if !ok || f.Severity != Info {
		t.Fatalf("expected an Info subdomain-policy-active finding, got %+v", report.Findings)
	}
}

func TestBuildDMARCSubdomainPolicyNoneIsCrit(t *testing.T) {
	result := &dmarc.DMARCResult{IsPresent: true, Policy: "reject", SubdomainPolicy: "none", Percentage: 100}
	report := Build("example.com", spf.SPFResult{}, result)

	f, ok := findByTitle(report.Findings, "DMARC policy is not active for subdomains")
	if !ok || f.Severity != Crit {
		t.Fatalf("expected a Crit sp=none finding, got %+v", report.Findings)
	}
}

func TestBuildDMARCSubdomainPolicyInheritsNoneFromPolicy(t *testing.T) {
	// No "sp" tag published at all, and "p=none": per RFC 7489 §6.3,
	// subdomains inherit the organizational policy, so this must still
	// be flagged Crit even though SubdomainPolicy itself is empty.
	result := &dmarc.DMARCResult{IsPresent: true, Policy: "none", SubdomainPolicy: "", Percentage: 100}
	report := Build("example.com", spf.SPFResult{}, result)

	f, ok := findByTitle(report.Findings, "DMARC policy is not active for subdomains")
	if !ok || f.Severity != Crit {
		t.Fatalf("expected a Crit finding via sp inheriting p=none, got %+v", report.Findings)
	}
	if f.Detail == "'sp=none' is the equivalent of having no DMARC record for subdomains, allowing spoofed mail." {
		t.Error("Detail should distinguish inherited none from an explicit sp=none tag")
	}
}

func TestBuildDMARCSubdomainPolicyInheritsNonNoneFromPolicy(t *testing.T) {
	// No "sp" tag published, and "p=reject": subdomains inherit a
	// non-none policy, so this must be Info, not Crit.
	result := &dmarc.DMARCResult{IsPresent: true, Policy: "reject", SubdomainPolicy: "", Percentage: 100}
	report := Build("example.com", spf.SPFResult{}, result)

	f, ok := findByTitle(report.Findings, "DMARC policy is active for subdomains")
	if !ok || f.Severity != Info {
		t.Fatalf("expected an Info finding via sp inheriting a non-none p, got %+v", report.Findings)
	}
}

func TestBuildDMARCExplicitSubdomainPolicyOverridesNonePolicy(t *testing.T) {
	// "p=none" but an explicit "sp=reject": the explicit tag must win
	// over inheritance, so subdomains are still protected (Info).
	result := &dmarc.DMARCResult{IsPresent: true, Policy: "none", SubdomainPolicy: "reject", Percentage: 100}
	report := Build("example.com", spf.SPFResult{}, result)

	f, ok := findByTitle(report.Findings, "DMARC policy is active for subdomains")
	if !ok || f.Severity != Info {
		t.Fatalf("expected an Info finding: explicit sp=reject should override inheritance, got %+v", report.Findings)
	}
}

func TestBuildReportCarriesDomainAndRawResults(t *testing.T) {
	spfResult := spf.SPFResult{RawRecord: "v=spf1 -all"}
	dmarcResult := &dmarc.DMARCResult{IsPresent: true, Policy: "reject", Percentage: 100}

	report := Build("example.com", spfResult, dmarcResult)

	if report.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", report.Domain, "example.com")
	}
	if report.SPF.RawRecord != spfResult.RawRecord {
		t.Errorf("SPF = %+v, want %+v", report.SPF, spfResult)
	}
	if report.DMARC != dmarcResult {
		t.Errorf("DMARC = %+v, want the same pointer passed in", report.DMARC)
	}
}

// TestBuildFindingCodeIsStableAcrossSeverity guards the whole point of
// Code: automation should be able to match on it regardless of which
// severity a rule happened to produce this run. The IP-count rule is a
// good test case since it alone spans all three severities.
func TestBuildFindingCodeIsStableAcrossSeverity(t *testing.T) {
	tests := []struct {
		name     string
		totalIPs uint64
		want     Severity
	}{
		{name: "info tier", totalIPs: 500, want: Info},
		{name: "warn tier", totalIPs: 10_001, want: Warn},
		{name: "crit tier", totalIPs: 1_000_001, want: Crit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := spf.SPFResult{RawRecord: "v=spf1 -all", TotalIPs: tt.totalIPs}
			report := Build("example.com", result, nil)

			var found *Finding
			for i := range report.Findings {
				if report.Findings[i].Code == "spf_ip_count" {
					found = &report.Findings[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("no finding with code spf_ip_count, got %+v", report.Findings)
			}
			if found.Severity != tt.want {
				t.Errorf("Severity = %q, want %q", found.Severity, tt.want)
			}
		})
	}
}

// TestBuildFindingItemsIsNeverNil checks every finding a healthy,
// minimal report produces: Items must always be a non-nil, empty slice
// when a rule has no itemized detail, so JSON always emits [] and
// automation never has to special-case null.
func TestBuildFindingItemsIsNeverNil(t *testing.T) {
	spfResult := spf.SPFResult{RawRecord: "v=spf1 -all", HasHardFail: true}
	dmarcResult := &dmarc.DMARCResult{IsPresent: true, Policy: "reject", SubdomainPolicy: "reject", Percentage: 100}

	report := Build("example.com", spfResult, dmarcResult)

	for _, f := range report.Findings {
		if f.Items == nil {
			t.Errorf("Finding %q (%s) has nil Items, want a non-nil empty slice", f.Title, f.Code)
		}
	}
}
