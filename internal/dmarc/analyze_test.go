package dmarc

import (
	"context"
	"errors"
	"testing"
)

// fakeResolver is a spf.Resolver backed by fixed per-host records or
// errors, for tests that don't want to touch real DNS.
type fakeResolver struct {
	records map[string][]string
	errs    map[string]error
}

func (r *fakeResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	if err, ok := r.errs[host]; ok {
		return nil, err
	}
	return r.records[host], nil
}

func TestAnalyzeNoRecord(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"_dmarc.example.com": {"some unrelated txt record"},
	}}

	result, err := Analyze(context.Background(), "example.com", resolver)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if result.IsPresent {
		t.Errorf("IsPresent = true, want false: %+v", result)
	}
	if result.RUA == nil || result.RUF == nil {
		t.Errorf("RUA/RUF = %+v, want non-nil empty slices (so JSON emits [] rather than null)", result)
	}
}

func TestAnalyzeLookupFailureIsNotPresentNotError(t *testing.T) {
	resolver := &fakeResolver{errs: map[string]error{
		"_dmarc.example.com": errors.New("NXDOMAIN"),
	}}

	result, err := Analyze(context.Background(), "example.com", resolver)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if result.IsPresent {
		t.Errorf("IsPresent = true, want false: %+v", result)
	}
}

func TestAnalyzeFullRecord(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"_dmarc.example.com": {
			"v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:agg@example.com,mailto:agg2@example.com; ruf=mailto:forensic@example.com",
		},
	}}

	result, err := Analyze(context.Background(), "example.com", resolver)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if !result.IsPresent {
		t.Fatal("IsPresent = false, want true")
	}
	if result.Policy != "reject" {
		t.Errorf("Policy = %q, want %q", result.Policy, "reject")
	}
	if result.SubdomainPolicy != "quarantine" {
		t.Errorf("SubdomainPolicy = %q, want %q", result.SubdomainPolicy, "quarantine")
	}
	if result.Percentage != 50 {
		t.Errorf("Percentage = %d, want 50", result.Percentage)
	}
	wantRUA := []string{"mailto:agg@example.com", "mailto:agg2@example.com"}
	if !equalSlices(result.RUA, wantRUA) {
		t.Errorf("RUA = %v, want %v", result.RUA, wantRUA)
	}
	wantRUF := []string{"mailto:forensic@example.com"}
	if !equalSlices(result.RUF, wantRUF) {
		t.Errorf("RUF = %v, want %v", result.RUF, wantRUF)
	}
}

func TestAnalyzeMissingPctDefaultsTo100(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=none"},
	}}

	result, err := Analyze(context.Background(), "example.com", resolver)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if result.Percentage != 100 {
		t.Errorf("Percentage = %d, want 100 (default)", result.Percentage)
	}
	if result.SubdomainPolicy != "" {
		t.Errorf("SubdomainPolicy = %q, want empty when sp tag is absent", result.SubdomainPolicy)
	}
	if result.RUA == nil || result.RUF == nil {
		t.Errorf("RUA/RUF = %+v, want non-nil empty slices when rua/ruf tags are absent", result)
	}
}

func TestAnalyzeMalformedPctDefaultsTo100(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=none; pct=notanumber"},
	}}

	result, err := Analyze(context.Background(), "example.com", resolver)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if result.Percentage != 100 {
		t.Errorf("Percentage = %d, want 100 (default, since pct was unparseable)", result.Percentage)
	}
}

func TestAnalyzeMultipleCandidateRecordsIsNotPresent(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"_dmarc.example.com": {
			"v=DMARC1; p=reject",
			"v=DMARC1; p=none",
		},
	}}

	result, err := Analyze(context.Background(), "example.com", resolver)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if result.IsPresent {
		t.Errorf("IsPresent = true, want false: multiple candidate records is invalid per RFC 7489 §6.6.3, got %+v", result)
	}
}

func TestAnalyzeURIsWithWhitespaceAreTrimmed(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=none; rua=mailto:a@example.com ,  mailto:b@example.com"},
	}}

	result, err := Analyze(context.Background(), "example.com", resolver)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	want := []string{"mailto:a@example.com", "mailto:b@example.com"}
	if !equalSlices(result.RUA, want) {
		t.Errorf("RUA = %v, want %v", result.RUA, want)
	}
}

func TestAnalyzeContextAlreadyCanceledIsAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resolver := &fakeResolver{}
	if _, err := Analyze(ctx, "example.com", resolver); err == nil {
		t.Fatal("Analyze() error = nil, want error for an already-canceled context")
	}
}

func equalSlices(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
