package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/mentesan/mailseck/internal/dmarc"
	"github.com/mentesan/mailseck/internal/lookup"
	"github.com/mentesan/mailseck/internal/report"
	"github.com/mentesan/mailseck/internal/spf"
)

func TestExitCodeFor(t *testing.T) {
	tests := []struct {
		name string
		rep  report.Report
		want int
	}{
		{
			name: "no findings",
			rep:  report.Report{},
			want: exitOK,
		},
		{
			name: "only info and warn",
			rep: report.Report{Findings: []report.Finding{
				{Severity: report.Info}, {Severity: report.Warn},
			}},
			want: exitOK,
		},
		{
			name: "SPF lookup failed, no crit finding",
			rep: report.Report{
				SPF:      spf.SPFResult{Status: lookup.Error},
				DMARC:    &dmarc.DMARCResult{Status: lookup.Found},
				Findings: []report.Finding{{Severity: report.Warn}},
			},
			want: exitError,
		},
		{
			name: "DMARC lookup failed, with a crit finding",
			rep: report.Report{
				SPF:      spf.SPFResult{Status: lookup.NotFound},
				DMARC:    &dmarc.DMARCResult{Status: lookup.Error},
				Findings: []report.Finding{{Severity: report.Crit}, {Severity: report.Warn}},
			},
			want: exitError,
		},
		{
			name: "a crit finding anywhere",
			rep: report.Report{Findings: []report.Finding{
				{Severity: report.Info}, {Severity: report.Crit}, {Severity: report.Warn},
			}},
			want: exitCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeFor(tt.rep); got != tt.want {
				t.Errorf("exitCodeFor() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRenderReportChoosesFormat(t *testing.T) {
	rep := report.Report{Domain: "example.com", Findings: []report.Finding{
		{Severity: report.Info, Title: "SPF record is defined"},
	}}

	var textBuf bytes.Buffer
	if err := renderReport(&textBuf, rep, config{json: false}); err != nil {
		t.Fatalf("renderReport() text unexpected error: %v", err)
	}
	if !bytes.Contains(textBuf.Bytes(), []byte("SPF record is defined")) {
		t.Errorf("text output missing finding title: %s", textBuf.String())
	}

	var jsonBuf bytes.Buffer
	if err := renderReport(&jsonBuf, rep, config{json: true}); err != nil {
		t.Fatalf("renderReport() json unexpected error: %v", err)
	}
	if !bytes.Contains(jsonBuf.Bytes(), []byte(`"title": "SPF record is defined"`)) {
		t.Errorf("json output missing finding title: %s", jsonBuf.String())
	}
}

func TestRunMissingDomainReturnsExitError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{}, &stdout, &stderr, offlineDependencies(&fakeResolver{}))
	if got != exitError {
		t.Errorf("run() = %d, want %d (exitError)", got, exitError)
	}
	if stderr.Len() == 0 {
		t.Error("expected an error message on stderr")
	}
}

func TestRunInvalidDomainReturnsExitError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"-d", "not a domain"}, &stdout, &stderr, offlineDependencies(&fakeResolver{}))
	if got != exitError {
		t.Errorf("run() = %d, want %d (exitError)", got, exitError)
	}
}

func TestRunHelpReturnsExitOK(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"-h"}, &stdout, &stderr, offlineDependencies(&fakeResolver{}))
	if got != exitOK {
		t.Errorf("run() = %d, want %d (exitOK)", got, exitOK)
	}
}

// fakeResolver is an spf.Resolver backed by fixed per-host records or
// errors, recording every host it was asked about, so run can be tested
// end to end without network access.
type fakeResolver struct {
	records map[string][]string
	errs    map[string]error
	queried []string
}

func (r *fakeResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	r.queried = append(r.queried, host)
	if err, ok := r.errs[host]; ok {
		return nil, err
	}
	return r.records[host], nil
}

// offlineDependencies wires resolver into run together with an empty,
// offline cloud CIDR set, so no test touches the network or the on-disk
// CIDR cache.
func offlineDependencies(resolver spf.Resolver) dependencies {
	return dependencies{
		resolver: resolver,
		fetchCIDRs: func(context.Context, config) (map[string][]netip.Prefix, error) {
			return map[string][]netip.Prefix{}, nil
		},
	}
}

// notFoundErr is what the standard library resolver returns for both
// NXDOMAIN and NODATA.
func notFoundErr(host string) error {
	return &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// timeoutErr is what the standard library resolver returns when no
// server answers in time.
func timeoutErr(host string) error {
	return &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
}

// runResult is the observable outcome of one run call.
type runResult struct {
	code   int
	stdout string
	stderr string
}

func runOffline(resolver *fakeResolver, args ...string) runResult {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr, offlineDependencies(resolver))
	return runResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// decodeJSON decodes run's --json output generically, so tests can tell
// a JSON null apart from an empty string or array.
func decodeJSON(t *testing.T, stdout string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	return doc
}

// object returns doc[key] as a JSON object, failing the test otherwise.
func object(t *testing.T, doc map[string]any, key string) map[string]any {
	t.Helper()
	obj, ok := doc[key].(map[string]any)
	if !ok {
		t.Fatalf("%q = %#v, want a JSON object", key, doc[key])
	}
	return obj
}

// findings returns the decoded report's findings as JSON objects.
func findings(t *testing.T, doc map[string]any) []map[string]any {
	t.Helper()
	raw, ok := doc["findings"].([]any)
	if !ok {
		t.Fatalf("findings = %#v, want a JSON array", doc["findings"])
	}
	out := make([]map[string]any, 0, len(raw))
	for _, f := range raw {
		obj, ok := f.(map[string]any)
		if !ok {
			t.Fatalf("finding = %#v, want a JSON object", f)
		}
		out = append(out, obj)
	}
	return out
}

// hasFinding reports whether any finding has the given code and severity.
func hasFinding(fs []map[string]any, code string, severity report.Severity) bool {
	for _, f := range fs {
		if f["code"] == code && f["severity"] == string(severity) {
			return true
		}
	}
	return false
}

// findingsWithCodePrefix returns every finding whose code starts with
// prefix, e.g. "spf_" or "dmarc_".
func findingsWithCodePrefix(fs []map[string]any, prefix string) []map[string]any {
	var out []map[string]any
	for _, f := range fs {
		if code, _ := f["code"].(string); strings.HasPrefix(code, prefix) {
			out = append(out, f)
		}
	}
	return out
}

// Criteria 1 and 2: a domain without an SPF record is a critical finding,
// not a failed run, and DMARC is still analyzed.
func TestRunMissingSPFRecordStillAnalyzesDMARC(t *testing.T) {
	const dmarcRecord = "v=DMARC1; p=none; rua=mailto:r@example.com"

	tests := []struct {
		name    string
		records []string
		err     error
	}{
		{name: "name not found", err: notFoundErr("example.com")},
		{name: "TXT without v=spf1", records: []string{"google-site-verification=x"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &fakeResolver{records: map[string][]string{
				"example.com":        tt.records,
				"_dmarc.example.com": {dmarcRecord},
			}}
			if tt.err != nil {
				resolver.errs = map[string]error{"example.com": tt.err}
			}

			got := runOffline(resolver, "-d", "example.com", "--json")
			if got.code != exitCritical {
				t.Errorf("run() = %d, want %d (exitCritical), stderr: %s", got.code, exitCritical, got.stderr)
			}
			if got.stderr != "" {
				t.Errorf("stderr = %q, want empty: an absent record is not a failure", got.stderr)
			}

			doc := decodeJSON(t, got.stdout)
			spfObj, dmarcObj := object(t, doc, "spf"), object(t, doc, "dmarc")
			if spfObj["status"] != "not_found" || spfObj["is_present"] != false || spfObj["error"] != "" {
				t.Errorf("spf = %v, want status not_found, is_present false, error \"\"", spfObj)
			}
			if dmarcObj["status"] != "found" || dmarcObj["raw_record"] != dmarcRecord {
				t.Errorf("dmarc = %v, want status found and the published record", dmarcObj)
			}
			fs := findings(t, doc)
			if !hasFinding(fs, "spf_record", report.Crit) || !hasFinding(fs, "dmarc_policy", report.Crit) {
				t.Errorf("findings = %v, want spf_record crit and dmarc_policy crit", fs)
			}
		})
	}
}

// Criterion 3: a failed SPF lookup is reported, not fatal, DMARC still
// runs, and the exit code says the run could not vouch for the domain.
func TestRunSPFLookupErrorStillAnalyzesDMARC(t *testing.T) {
	resolver := &fakeResolver{
		records: map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}},
		errs:    map[string]error{"example.com": timeoutErr("example.com")},
	}

	got := runOffline(resolver, "-d", "example.com", "--json")
	if got.code != exitError {
		t.Errorf("run() = %d, want %d (exitError)", got.code, exitError)
	}
	if !slices.Contains(resolver.queried, "_dmarc.example.com") {
		t.Errorf("queried = %v, want _dmarc.example.com to have been looked up", resolver.queried)
	}

	doc := decodeJSON(t, got.stdout)
	spfObj := object(t, doc, "spf")
	if errMsg, _ := spfObj["error"].(string); spfObj["status"] != "error" || errMsg == "" {
		t.Errorf("spf = %v, want status error with a non-empty error", spfObj)
	}
	spfFindings := findingsWithCodePrefix(findings(t, doc), "spf_")
	if len(spfFindings) != 1 || !hasFinding(spfFindings, "spf_record", report.Warn) {
		t.Errorf("SPF findings = %v, want only spf_record warn", spfFindings)
	}

	lines := strings.Split(strings.TrimSuffix(got.stderr, "\n"), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "SPF") || !strings.Contains(lines[0], "example.com") {
		t.Errorf("stderr = %q, want one line naming SPF and the queried name", got.stderr)
	}
}

// Criterion 4: a failed DMARC lookup is not reported as an absent record,
// and gets no suggestion.
func TestRunDMARCLookupErrorIsNotAbsence(t *testing.T) {
	resolver := &fakeResolver{
		records: map[string][]string{"example.com": {"v=spf1 -all"}},
		errs:    map[string]error{"_dmarc.example.com": errors.New("SERVFAIL")},
	}

	got := runOffline(resolver, "-d", "example.com", "--json")
	if got.code != exitError {
		t.Errorf("run() = %d, want %d (exitError)", got.code, exitError)
	}

	doc := decodeJSON(t, got.stdout)
	if dmarcObj := object(t, doc, "dmarc"); dmarcObj["status"] != "error" {
		t.Errorf("dmarc.status = %v, want error", dmarcObj["status"])
	}
	for _, f := range findings(t, doc) {
		if f["title"] == "No DMARC record is defined" {
			t.Errorf("found %v: a failed lookup must not be reported as an absent record", f)
		}
	}
	if suggestion, ok := doc["dmarc_suggestion"]; !ok || suggestion != nil {
		t.Errorf("dmarc_suggestion = %#v, want null", suggestion)
	}
	if !strings.Contains(got.stderr, "DMARC") || !strings.Contains(got.stderr, "_dmarc.example.com") {
		t.Errorf("stderr = %q, want a line naming DMARC and _dmarc.example.com", got.stderr)
	}
}

// Criterion 5 (PRD §11): a domain with neither record exits 1, and both
// renderers report both critical findings.
func TestRunNoSPFNoDMARCReportsBothCriticalFindings(t *testing.T) {
	newResolver := func() *fakeResolver {
		return &fakeResolver{errs: map[string]error{
			"example.com":        notFoundErr("example.com"),
			"_dmarc.example.com": notFoundErr("_dmarc.example.com"),
		}}
	}

	jsonRun := runOffline(newResolver(), "-d", "example.com", "--json")
	if jsonRun.code != exitCritical {
		t.Errorf("run(--json) = %d, want %d (exitCritical)", jsonRun.code, exitCritical)
	}
	fs := findings(t, decodeJSON(t, jsonRun.stdout))
	if !hasFinding(fs, "spf_record", report.Crit) || !hasFinding(fs, "dmarc_record", report.Crit) {
		t.Errorf("JSON findings = %v, want spf_record crit and dmarc_record crit", fs)
	}

	textRun := runOffline(newResolver(), "-d", "example.com", "--no-color")
	if textRun.code != exitCritical {
		t.Errorf("run(text) = %d, want %d (exitCritical)", textRun.code, exitCritical)
	}
	for _, want := range []string{"[CRIT] No SPF record is defined", "[CRIT] No DMARC record is defined"} {
		if !strings.Contains(textRun.stdout, want) {
			t.Errorf("text output missing %q:\n%s", want, textRun.stdout)
		}
	}
}

// Criterion 6: a record exceeding the lookup budget is found, and its
// spf_analysis finding serializes items as [], never null.
func TestRunLookupLimitFindingHasEmptyItems(t *testing.T) {
	records := map[string][]string{
		"example.com":        {"v=spf1 include:h1.example -all"},
		"_dmarc.example.com": {"v=DMARC1; p=reject"},
	}
	for i := 1; i <= 10; i++ {
		records[fmt.Sprintf("h%d.example", i)] = []string{fmt.Sprintf("v=spf1 include:h%d.example", i+1)}
	}

	got := runOffline(&fakeResolver{records: records}, "-d", "example.com", "--json")

	var raw struct {
		SPF      struct{ Status string } `json:"spf"`
		Findings []json.RawMessage       `json:"findings"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &raw); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, got.stdout)
	}
	if raw.SPF.Status != "found" {
		t.Errorf("spf.status = %q, want found", raw.SPF.Status)
	}

	var analysis json.RawMessage
	for _, f := range raw.Findings {
		if bytes.Contains(f, []byte(`"code": "spf_analysis"`)) {
			analysis = f
		}
	}
	if analysis == nil {
		t.Fatalf("no spf_analysis finding in:\n%s", got.stdout)
	}
	if !bytes.Contains(analysis, []byte(`"severity": "crit"`)) || !bytes.Contains(analysis, []byte(`"items": []`)) {
		t.Errorf("spf_analysis finding = %s, want severity crit and \"items\": []", analysis)
	}
}

// Criterion 7: every SPF x DMARC status combination serializes without
// null in the status fields and collections, and honors the invariants
// tying is_present, error and the record fields to status.
func TestRunJSONHonorsStatusInvariantsForEveryCombination(t *testing.T) {
	spfCases := map[lookup.Status]func(r *fakeResolver){
		lookup.Found:    func(r *fakeResolver) { r.records["example.com"] = []string{"v=spf1 -all"} },
		lookup.NotFound: func(r *fakeResolver) { r.errs["example.com"] = notFoundErr("example.com") },
		lookup.Error:    func(r *fakeResolver) { r.errs["example.com"] = timeoutErr("example.com") },
	}
	dmarcCases := map[lookup.Status]func(r *fakeResolver){
		lookup.Found: func(r *fakeResolver) {
			r.records["_dmarc.example.com"] = []string{"v=DMARC1; p=reject; rua=mailto:r@example.com"}
		},
		lookup.NotFound: func(r *fakeResolver) { r.errs["_dmarc.example.com"] = notFoundErr("_dmarc.example.com") },
		lookup.Error:    func(r *fakeResolver) { r.errs["_dmarc.example.com"] = errors.New("SERVFAIL") },
	}

	for spfStatus, setSPF := range spfCases {
		for dmarcStatus, setDMARC := range dmarcCases {
			t.Run(fmt.Sprintf("spf=%s/dmarc=%s", spfStatus, dmarcStatus), func(t *testing.T) {
				resolver := &fakeResolver{records: map[string][]string{}, errs: map[string]error{}}
				setSPF(resolver)
				setDMARC(resolver)

				got := runOffline(resolver, "-d", "example.com", "--json")
				doc := decodeJSON(t, got.stdout)

				assertToolVersion(t, got.stdout, doc)
				assertCheckInvariants(t, object(t, doc, "spf"), spfStatus, "irresolvable_hosts", "overlaps")
				assertCheckInvariants(t, object(t, doc, "dmarc"), dmarcStatus, "rua", "ruf")
				for _, f := range findings(t, doc) {
					if _, ok := f["items"].([]any); !ok {
						t.Errorf("finding %v: items = %#v, want an array", f["code"], f["items"])
					}
				}

				wantCode := exitOK
				switch {
				case spfStatus == lookup.Error || dmarcStatus == lookup.Error:
					wantCode = exitError
				case spfStatus == lookup.NotFound || dmarcStatus == lookup.NotFound:
					wantCode = exitCritical
				}
				if got.code != wantCode {
					t.Errorf("run() = %d, want %d", got.code, wantCode)
				}
			})
		}
	}
}

// assertCheckInvariants checks one decoded "spf" or "dmarc" object
// against the status contract; collections names its array fields.
func assertCheckInvariants(t *testing.T, check map[string]any, want lookup.Status, collections ...string) {
	t.Helper()
	status, ok := check["status"].(string)
	if !ok || status != string(want) {
		t.Fatalf("status = %#v, want %q", check["status"], want)
	}
	errMsg, ok := check["error"].(string)
	if !ok {
		t.Fatalf("error = %#v, want a string", check["error"])
	}
	if check["is_present"] != (want == lookup.Found) {
		t.Errorf("is_present = %v with status %q", check["is_present"], status)
	}
	if (errMsg != "") != (want == lookup.Error) {
		t.Errorf("error = %q with status %q", errMsg, status)
	}
	for _, name := range collections {
		items, ok := check[name].([]any)
		if !ok {
			t.Errorf("%s = %#v, want an array", name, check[name])
			continue
		}
		if want != lookup.Found && len(items) != 0 {
			t.Errorf("%s = %v with status %q, want []", name, items, status)
		}
	}
	if want != lookup.Found && check["raw_record"] != "" {
		t.Errorf("raw_record = %#v with status %q, want \"\"", check["raw_record"], status)
	}
}

// assertToolVersion checks that the serialized report carries a non-empty
// top-level tool_version equal to the running binary's version.
func assertToolVersion(t *testing.T, stdout string, doc map[string]any) {
	t.Helper()
	want := fmt.Sprintf(`"tool_version": %q`, version())
	if version() == "" || !strings.Contains(stdout, want) {
		t.Errorf("stdout does not contain %s:\n%s", want, stdout)
	}
	if v, ok := doc["tool_version"].(string); !ok || v == "" {
		t.Errorf("tool_version = %#v, want a non-empty string", doc["tool_version"])
	}
}

// Criterion 1: --version prints exactly "mailseck <version>" and exits 0.
func TestRunVersionPrintsVersion(t *testing.T) {
	got := runOffline(&fakeResolver{}, "--version")
	if got.code != exitOK {
		t.Errorf("run() = %d, want %d (exitOK)", got.code, exitOK)
	}
	if want := "mailseck " + version() + "\n"; got.stdout != want {
		t.Errorf("stdout = %q, want %q", got.stdout, want)
	}
	if got.stderr != "" {
		t.Errorf("stderr = %q, want empty", got.stderr)
	}
}

// Criterion 2: --version takes precedence; an invalid domain is neither
// validated nor queried, and no CIDR is loaded.
func TestRunVersionSkipsDomainValidationAndLookups(t *testing.T) {
	var stdout, stderr bytes.Buffer
	deps := dependencies{
		resolver: failingResolver{t},
		fetchCIDRs: func(context.Context, config) (map[string][]netip.Prefix, error) {
			t.Error("fetchCIDRs called with --version")
			return nil, errors.New("unexpected fetch")
		},
	}

	code := run([]string{"--version", "-d", "nao valido!"}, &stdout, &stderr, deps)
	if code != exitOK {
		t.Errorf("run() = %d, want %d (exitOK), stderr: %s", code, exitOK, stderr.String())
	}
	if want := "mailseck " + version() + "\n"; stdout.String() != want {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}
}

// Criterion 3: a flag parsing error still wins over --version.
func TestRunVersionWithUnknownFlagIsAnError(t *testing.T) {
	got := runOffline(&fakeResolver{}, "--version", "--flag-inexistente")
	if got.code != exitError {
		t.Errorf("run() = %d, want %d (exitError)", got.code, exitError)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty", got.stdout)
	}
}

// failingResolver fails the test on any lookup.
type failingResolver struct{ t *testing.T }

func (r failingResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	r.t.Errorf("LookupTXT(%q) called, want no DNS lookup", host)
	return nil, errors.New("unexpected lookup")
}
