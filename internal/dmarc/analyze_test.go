package dmarc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/mentesan/mailseck/internal/lookup"
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

	result := Analyze(context.Background(), "example.com", resolver)
	if result.IsPresent {
		t.Errorf("IsPresent = true, want false: %+v", result)
	}
	if result.RUA == nil || result.RUF == nil {
		t.Errorf("RUA/RUF = %+v, want non-nil empty slices (so JSON emits [] rather than null)", result)
	}
}

func TestAnalyzeLookupStatus(t *testing.T) {
	tests := []struct {
		name       string
		records    []string
		err        error
		wantStatus lookup.Status
	}{
		{
			name:       "single record",
			records:    []string{"v=DMARC1; p=none; rua=mailto:r@example.com"},
			wantStatus: lookup.Found,
		},
		{
			name:       "TXT without v=DMARC1",
			records:    []string{"some unrelated txt record"},
			wantStatus: lookup.NotFound,
		},
		{
			name:       "more than one candidate record",
			records:    []string{"v=DMARC1; p=reject", "v=DMARC1; p=none"},
			wantStatus: lookup.NotFound,
		},
		{
			name:       "name not found",
			err:        &net.DNSError{Err: "no such host", Name: "_dmarc.example.com", IsNotFound: true},
			wantStatus: lookup.NotFound,
		},
		{
			name:       "timeout",
			err:        &net.DNSError{Err: "i/o timeout", Name: "_dmarc.example.com", IsTimeout: true},
			wantStatus: lookup.Error,
		},
		{
			name:       "generic error",
			err:        errors.New("SERVFAIL"),
			wantStatus: lookup.Error,
		},
		{
			name:       "context canceled during lookup",
			err:        context.Canceled,
			wantStatus: lookup.Error,
		},
		{
			name:       "context deadline exceeded during lookup",
			err:        fmt.Errorf("lookup _dmarc.example.com: %w", context.DeadlineExceeded),
			wantStatus: lookup.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &fakeResolver{records: map[string][]string{"_dmarc.example.com": tt.records}}
			if tt.err != nil {
				resolver.errs = map[string]error{"_dmarc.example.com": tt.err}
			}

			result := Analyze(context.Background(), "example.com", resolver)
			if result.Status != tt.wantStatus {
				t.Fatalf("Status = %q, want %q", result.Status, tt.wantStatus)
			}
			assertStatusInvariants(t, result)
			if tt.wantStatus == lookup.Error && result.Error != tt.err.Error() {
				t.Errorf("Error = %q, want the lookup error's message %q", result.Error, tt.err.Error())
			}
		})
	}
}

// assertStatusInvariants checks the DMARCResult contract tying IsPresent,
// Error and the record fields to Status.
func assertStatusInvariants(t *testing.T, result *DMARCResult) {
	t.Helper()
	if result.IsPresent != (result.Status == lookup.Found) {
		t.Errorf("IsPresent = %v with Status %q", result.IsPresent, result.Status)
	}
	if (result.Error != "") != (result.Status == lookup.Error) {
		t.Errorf("Error = %q with Status %q", result.Error, result.Status)
	}
	if result.RUA == nil || result.RUF == nil {
		t.Errorf("RUA/RUF = %v/%v, want non-nil slices", result.RUA, result.RUF)
	}
	if result.Status == lookup.Found {
		return
	}
	if result.RawRecord != "" || result.Policy != "" || result.SubdomainPolicy != "" ||
		len(result.RUA) != 0 || len(result.RUF) != 0 {
		t.Errorf("Status %q with non-empty record fields: %+v", result.Status, result)
	}
}

func TestRecordName(t *testing.T) {
	if got, want := RecordName("example.com"), "_dmarc.example.com"; got != want {
		t.Errorf("RecordName() = %q, want %q", got, want)
	}
}

func TestAnalyzeFullRecord(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"_dmarc.example.com": {
			"v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:agg@example.com,mailto:agg2@example.com; ruf=mailto:forensic@example.com",
		},
	}}

	result := Analyze(context.Background(), "example.com", resolver)
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

	result := Analyze(context.Background(), "example.com", resolver)
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

	result := Analyze(context.Background(), "example.com", resolver)
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

	result := Analyze(context.Background(), "example.com", resolver)
	if result.IsPresent {
		t.Errorf("IsPresent = true, want false: multiple candidate records is invalid per RFC 7489 §6.6.3, got %+v", result)
	}
}

func TestAnalyzeURIsWithWhitespaceAreTrimmed(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=none; rua=mailto:a@example.com ,  mailto:b@example.com"},
	}}

	result := Analyze(context.Background(), "example.com", resolver)
	want := []string{"mailto:a@example.com", "mailto:b@example.com"}
	if !equalSlices(result.RUA, want) {
		t.Errorf("RUA = %v, want %v", result.RUA, want)
	}
}

func TestAnalyzeContextAlreadyCanceledIsAnErrorStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resolver := &fakeResolver{records: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=reject"},
	}}
	result := Analyze(ctx, "example.com", resolver)
	if result.Status != lookup.Error {
		t.Fatalf("Status = %q, want %q for an already-canceled context", result.Status, lookup.Error)
	}
	if result.Error != context.Canceled.Error() {
		t.Errorf("Error = %q, want %q", result.Error, context.Canceled.Error())
	}
	assertStatusInvariants(t, result)
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
