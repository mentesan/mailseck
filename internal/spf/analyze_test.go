package spf

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// fakeResolver is a Resolver backed by fixed per-host records or errors,
// for tests that don't want to touch real DNS.
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

func TestAnalyzeNoSPFRecord(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.com": {"some unrelated txt record"},
	}}

	result, err := Analyze(context.Background(), resolver, "example.com", nil)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if result.RawRecord != "" {
		t.Errorf("RawRecord = %q, want empty", result.RawRecord)
	}
	if result.TotalLookups != 0 || result.TotalIPs != 0 || result.HasHardFail {
		t.Errorf("Analyze() = %+v, want zero-value result", result)
	}
}

func TestAnalyzeRootResolutionFailureIsAnError(t *testing.T) {
	wantErr := errors.New("SERVFAIL")
	resolver := &fakeResolver{errs: map[string]error{"example.com": wantErr}}

	_, err := Analyze(context.Background(), resolver, "example.com", nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Analyze() error = %v, want wrapping %v", err, wantErr)
	}
}

func TestAnalyzeHardFail(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.com": {"v=spf1 ip4:203.0.113.0/24 -all"},
	}}

	result, err := Analyze(context.Background(), resolver, "example.com", nil)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if !result.HasHardFail {
		t.Error("HasHardFail = false, want true for -all")
	}
	if result.TotalIPs != 256 {
		t.Errorf("TotalIPs = %d, want 256", result.TotalIPs)
	}
	if result.TotalLookups != 0 {
		t.Errorf("TotalLookups = %d, want 0 (ip4 does not consume a lookup)", result.TotalLookups)
	}
}

func TestAnalyzeSoftFail(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.com": {"v=spf1 ip4:203.0.113.0/24 ~all"},
	}}

	result, err := Analyze(context.Background(), resolver, "example.com", nil)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if result.HasHardFail {
		t.Error("HasHardFail = true, want false for ~all")
	}
}

func TestAnalyzeNoAllMechanismAtAll(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.com": {"v=spf1 ip4:203.0.113.0/24"},
	}}

	result, err := Analyze(context.Background(), resolver, "example.com", nil)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if result.HasHardFail {
		t.Error("HasHardFail = true, want false: no all mechanism was present at all")
	}
}

func TestAnalyzeIncludeAllDoesNotSetHardFail(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.com": {"v=spf1 include:other.com"},
		"other.com":   {"v=spf1 ip4:10.0.0.0/8 -all"},
	}}

	result, err := Analyze(context.Background(), resolver, "example.com", nil)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if result.HasHardFail {
		t.Error("HasHardFail = true, want false: an include target's -all must not affect the parent")
	}
	if result.TotalLookups != 1 {
		t.Errorf("TotalLookups = %d, want 1", result.TotalLookups)
	}
	if result.TotalIPs != 1<<24 {
		t.Errorf("TotalIPs = %d, want %d", result.TotalIPs, uint64(1)<<24)
	}
}

func TestAnalyzeRedirectAllReplacesEvaluation(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.com": {"v=spf1 redirect=other.com"},
		"other.com":   {"v=spf1 ip4:10.0.0.0/8 -all"},
	}}

	result, err := Analyze(context.Background(), resolver, "example.com", nil)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if !result.HasHardFail {
		t.Error("HasHardFail = false, want true: a redirect target's -all replaces the parent's evaluation")
	}
	if result.TotalLookups != 1 {
		t.Errorf("TotalLookups = %d, want 1", result.TotalLookups)
	}
}

func TestAnalyzeLookupConsumingMechanismsAreCountedWithoutResolving(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.com": {"v=spf1 a mx ptr exists:%{i}.example.com -all"},
	}}

	result, err := Analyze(context.Background(), resolver, "example.com", nil)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if result.TotalLookups != 4 {
		t.Errorf("TotalLookups = %d, want 4 (a, mx, ptr, exists)", result.TotalLookups)
	}
	if !result.HasHardFail {
		t.Error("HasHardFail = false, want true")
	}
}

func TestAnalyzeExceedingLookupLimitStops(t *testing.T) {
	records := map[string][]string{
		"root.example": {"v=spf1 include:h1.example -all"},
	}
	for i := 1; i <= 10; i++ {
		records[fmt.Sprintf("h%d.example", i)] = []string{
			fmt.Sprintf("v=spf1 include:h%d.example", i+1),
		}
	}
	resolver := &fakeResolver{records: records}

	result, err := Analyze(context.Background(), resolver, "root.example", nil)
	if !errors.Is(err, ErrLookupLimitExceeded) {
		t.Fatalf("Analyze() error = %v, want wrapping ErrLookupLimitExceeded", err)
	}
	if result.TotalLookups != 11 {
		t.Errorf("TotalLookups = %d, want 11 (stops right after exceeding the budget)", result.TotalLookups)
	}
}

func TestAnalyzeCyclicReference(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"a.example": {"v=spf1 include:b.example"},
		"b.example": {"v=spf1 include:a.example"},
	}}

	result, err := Analyze(context.Background(), resolver, "a.example", nil)
	if !errors.Is(err, ErrCyclicReference) {
		t.Fatalf("Analyze() error = %v, want wrapping ErrCyclicReference", err)
	}
	if result.TotalLookups != 2 {
		t.Errorf("TotalLookups = %d, want 2", result.TotalLookups)
	}
}

// TestAnalyzeSelfReferenceTerminatesWithoutHanging directly proves that a
// cyclic SPF chain stops instead of recursing forever (and eventually
// blowing the goroutine stack): it runs Analyze in a goroutine and fails
// the test if it does not return well within a couple of seconds.
func TestAnalyzeSelfReferenceTerminatesWithoutHanging(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"self.example": {"v=spf1 include:self.example"},
	}}

	done := make(chan error, 1)
	go func() {
		_, err := Analyze(context.Background(), resolver, "self.example", nil)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrCyclicReference) {
			t.Fatalf("Analyze() error = %v, want wrapping ErrCyclicReference", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Analyze() did not return within 2s; likely stuck recursing")
	}
}

func TestAnalyzeIrresolvableHostDoesNotAbort(t *testing.T) {
	resolveErr := errors.New("NXDOMAIN")
	resolver := &fakeResolver{
		records: map[string][]string{
			"example.com": {"v=spf1 include:broken.example ip4:198.51.100.0/24 -all"},
		},
		errs: map[string]error{"broken.example": resolveErr},
	}

	result, err := Analyze(context.Background(), resolver, "example.com", nil)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if len(result.IrresolvableHosts) != 1 || result.IrresolvableHosts[0] != "broken.example" {
		t.Errorf("IrresolvableHosts = %v, want [broken.example]", result.IrresolvableHosts)
	}
	if !result.HasHardFail {
		t.Error("HasHardFail = false, want true")
	}
	if result.TotalIPs != 256 {
		t.Errorf("TotalIPs = %d, want 256", result.TotalIPs)
	}
	if result.TotalLookups != 1 {
		t.Errorf("TotalLookups = %d, want 1", result.TotalLookups)
	}
}

func TestAnalyzeOverlapDetection(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.com": {"v=spf1 ip4:203.0.113.0/24 -all"},
	}}
	cidrs := map[string][]netip.Prefix{
		"AWS": {netip.MustParsePrefix("203.0.113.0/25")},
	}

	result, err := Analyze(context.Background(), resolver, "example.com", cidrs)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	want := Overlap{
		SPFPrefix:   netip.MustParsePrefix("203.0.113.0/24"),
		CloudPrefix: netip.MustParsePrefix("203.0.113.0/25"),
		Provider:    "AWS",
	}
	if len(result.Overlaps) != 1 || result.Overlaps[0] != want {
		t.Errorf("Overlaps = %v, want [%v]", result.Overlaps, want)
	}
}

func TestAnalyzeNoOverlapWithUnrelatedCIDR(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.com": {"v=spf1 ip4:203.0.113.0/24 -all"},
	}}
	cidrs := map[string][]netip.Prefix{
		"AWS": {netip.MustParsePrefix("198.51.100.0/24")},
	}

	result, err := Analyze(context.Background(), resolver, "example.com", cidrs)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if len(result.Overlaps) != 0 {
		t.Errorf("Overlaps = %v, want none", result.Overlaps)
	}
}
