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

// TestAnalyzeDiamondIncludeIsNotACycle reproduces a real false positive
// found in production: otima.digital's SPF record includes both
// _spf.rdstation.com.br and sendgrid.net directly, but
// _spf.rdstation.com.br's own record *also* includes sendgrid.net. That
// is an ordinary diamond shape (two unrelated branches sharing a
// provider), not a cycle -- sendgrid.net is never its own ancestor. A
// visited set that never forgets a host once seen would misreport this
// exact case as ErrCyclicReference.
func TestAnalyzeDiamondIncludeIsNotACycle(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.digital": {
			"v=spf1 include:_spf.rdstation.example include:sendgrid.example -all",
		},
		"_spf.rdstation.example": {"v=spf1 include:sendgrid.example ?all"},
		"sendgrid.example":       {"v=spf1 ip4:167.89.0.0/17 ~all"},
	}}

	result, err := Analyze(context.Background(), resolver, "example.digital", nil)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	// sendgrid.example is resolved twice (once via rdstation, once
	// directly), so it contributes to TotalIPs twice -- that is
	// expected and matches how a real SPF evaluator re-resolves a
	// repeated include; the point of this test is only that it is not
	// an error.
	if result.TotalIPs == 0 {
		t.Error("TotalIPs = 0, want sendgrid.example's range counted at least once")
	}
}

// TestAnalyzeCycleNotTouchingRootIsStillDetected guards the fix for the
// diamond false positive above: a genuine cycle several levels deep,
// where none of the participants is the domain originally passed to
// Analyze, must still be caught.
func TestAnalyzeCycleNotTouchingRootIsStillDetected(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"root.example": {"v=spf1 include:x.example -all"},
		"x.example":    {"v=spf1 include:y.example"},
		"y.example":    {"v=spf1 include:x.example"},
	}}

	_, err := Analyze(context.Background(), resolver, "root.example", nil)
	if !errors.Is(err, ErrCyclicReference) {
		t.Fatalf("Analyze() error = %v, want wrapping ErrCyclicReference", err)
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
		Host:        "example.com",
		SPFPrefix:   netip.MustParsePrefix("203.0.113.0/24"),
		CloudPrefix: netip.MustParsePrefix("203.0.113.0/25"),
		Provider:    "AWS",
	}
	if len(result.Overlaps) != 1 || result.Overlaps[0] != want {
		t.Errorf("Overlaps = %v, want [%v]", result.Overlaps, want)
	}
}

// TestAnalyzeOverlapHostAttributesToTheRightLinkInTheChain proves the
// point of the Host field: two different SPF-permitted ranges overlap
// the same cloud provider, but one comes from the root record and the
// other from an include several links away, so each Overlap must name
// its own true origin, not just "the domain being analyzed".
func TestAnalyzeOverlapHostAttributesToTheRightLinkInTheChain(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.com": {
			"v=spf1 ip4:203.0.113.0/24 include:vendor-a.example include:vendor-b.example -all",
		},
		"vendor-a.example":       {"v=spf1 ip4:198.51.100.0/24 -all"},
		"vendor-b.example":       {"v=spf1 include:vendor-b-relay.example -all"},
		"vendor-b-relay.example": {"v=spf1 ip4:192.0.2.0/24 -all"},
	}}
	cidrs := map[string][]netip.Prefix{
		"AWS": {
			netip.MustParsePrefix("203.0.113.0/25"),
			netip.MustParsePrefix("198.51.100.0/25"),
			netip.MustParsePrefix("192.0.2.0/25"),
		},
	}

	result, err := Analyze(context.Background(), resolver, "example.com", cidrs)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}

	hostFor := make(map[string]string, len(result.Overlaps))
	for _, overlap := range result.Overlaps {
		hostFor[overlap.SPFPrefix.String()] = overlap.Host
	}

	want := map[string]string{
		"203.0.113.0/24":  "example.com",
		"198.51.100.0/24": "vendor-a.example",
		"192.0.2.0/24":    "vendor-b-relay.example",
	}
	for prefix, wantHost := range want {
		if hostFor[prefix] != wantHost {
			t.Errorf("Host for %s = %q, want %q (full: %+v)", prefix, hostFor[prefix], wantHost, result.Overlaps)
		}
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

// TestAnalyzeTrustedMailVendorIncludeIsNotReportedAsOverlap reproduces a
// real false positive found in production: a domain whose SPF record
// just includes Microsoft 365's own spf.protection.outlook.com. That
// record's ranges are Exchange Online Protection's own outbound mail
// infrastructure, but they sit inside Azure's publicly-advertised
// address space (Microsoft operates both), so Azure's CIDR feed also
// lists sub-ranges of them. This includes 40.107.0.0/16, a range an
// earlier, IP-based version of this false-positive fix (copied from the
// reference tool) did not know about and still flagged -- which is
// exactly why trust is now keyed by the vendor's hostname instead.
func TestAnalyzeTrustedMailVendorIncludeIsNotReportedAsOverlap(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.com.br": {"v=spf1 include:spf.protection.outlook.com -all"},
		"spf.protection.outlook.com": {
			"v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip4:52.100.0.0/15 -all",
		},
	}}
	cidrs := map[string][]netip.Prefix{
		// Real sub-ranges Azure's own published CIDR feed lists inside
		// Microsoft's EOP ranges, as observed against the live feed.
		"Azure": {
			netip.MustParsePrefix("40.93.136.0/24"),
			netip.MustParsePrefix("40.107.39.0/24"),
		},
	}

	result, err := Analyze(context.Background(), resolver, "example.com.br", cidrs)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if len(result.Overlaps) != 0 {
		t.Errorf("Overlaps = %v, want none: spf.protection.outlook.com is a trusted first-party mail host", result.Overlaps)
	}
	// The ranges must still count toward TotalIPs: they are real,
	// permitted sender ranges, just not a spoofing risk.
	if result.TotalIPs == 0 {
		t.Error("TotalIPs = 0, want the trusted vendor's ranges to still be counted")
	}
}

// TestAnalyzeTrustPropagatesTransitivelyThroughTrustedChain checks that
// trust, once earned by reaching a known vendor hostname, carries
// forward through whatever that vendor's own record includes next, even
// via an intermediary the customer controls.
func TestAnalyzeTrustPropagatesTransitivelyThroughTrustedChain(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.com":                {"v=spf1 include:relay.example -all"},
		"relay.example":              {"v=spf1 include:spf.protection.outlook.com"},
		"spf.protection.outlook.com": {"v=spf1 ip4:40.92.0.0/15 -all"},
	}}
	cidrs := map[string][]netip.Prefix{
		"Azure": {netip.MustParsePrefix("40.93.136.0/24")},
	}

	result, err := Analyze(context.Background(), resolver, "example.com", cidrs)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if len(result.Overlaps) != 0 {
		t.Errorf("Overlaps = %v, want none: trust should propagate through the intermediary include", result.Overlaps)
	}
}

// TestAnalyzeUntrustedIncludeStillReportsOverlap guards against the
// trust fix swallowing real overlaps: a customer-controlled include
// that happens to authorize the very same Microsoft range directly,
// without going through the trusted hostname, must still be flagged.
// Trust is earned by the hostname doing the including, not by the IP
// range itself.
func TestAnalyzeUntrustedIncludeStillReportsOverlap(t *testing.T) {
	resolver := &fakeResolver{records: map[string][]string{
		"example.com":    {"v=spf1 include:vendor.example -all"},
		"vendor.example": {"v=spf1 ip4:40.92.0.0/15 -all"},
	}}
	cidrs := map[string][]netip.Prefix{
		"Azure": {netip.MustParsePrefix("40.93.136.0/24")},
	}

	result, err := Analyze(context.Background(), resolver, "example.com", cidrs)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if len(result.Overlaps) != 1 {
		t.Fatalf("Overlaps = %v, want exactly one: vendor.example is not a trusted hostname", result.Overlaps)
	}
}
