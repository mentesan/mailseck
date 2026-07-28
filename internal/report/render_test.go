package report

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/mentesan/mailseck/internal/dmarc"
	"github.com/mentesan/mailseck/internal/spf"
)

func sampleReport() Report {
	return Report{
		Domain: "example.com",
		SPF:    spf.SPFResult{RawRecord: "v=spf1 -all", HasHardFail: true},
		DMARC:  &dmarc.DMARCResult{IsPresent: true, Policy: "reject", Percentage: 100},
		Findings: []Finding{
			{Severity: Crit, Title: "No SPF record is defined", Detail: "Mail can be easily spoofed."},
			{Severity: Warn, Title: "Directive leaves action ambiguous", Detail: "Ambiguous action."},
			{Severity: Info, Title: "DMARC record is defined", Detail: "SPF policy is less ambiguous."},
		},
	}
}

func TestShouldUseColor(t *testing.T) {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer devNull.Close()

	tmpFile, err := os.CreateTemp(t.TempDir(), "render-test-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer tmpFile.Close()

	tests := []struct {
		name    string
		w       io.Writer
		noColor bool
		want    bool
	}{
		{name: "noColor always wins, even on a terminal", w: devNull, noColor: true, want: false},
		{name: "bytes.Buffer is never a terminal", w: &bytes.Buffer{}, noColor: false, want: false},
		{name: "a regular file is not a terminal", w: tmpFile, noColor: false, want: false},
		{name: "a character device is a terminal", w: devNull, noColor: false, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldUseColor(tt.w, tt.noColor); got != tt.want {
				t.Errorf("shouldUseColor() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRenderTextNoColorHasNoANSICodes(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderText(&buf, sampleReport(), true); err != nil {
		t.Fatalf("RenderText() unexpected error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "\033[") {
		t.Errorf("output contains ANSI escape codes with noColor=true:\n%s", out)
	}
	for _, want := range []string{"example.com", "[CRIT]", "[WARN]", "[INFO]", "No SPF record is defined", "Mail can be easily spoofed."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderTextNonTerminalWriterNeverColorsEvenWithoutNoColor(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderText(&buf, sampleReport(), false); err != nil {
		t.Fatalf("RenderText() unexpected error: %v", err)
	}

	if strings.Contains(buf.String(), "\033[") {
		t.Errorf("output contains ANSI escape codes even though the writer is not a terminal:\n%s", buf.String())
	}
}

func TestRenderTextNoFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderText(&buf, Report{Domain: "example.com"}, true); err != nil {
		t.Fatalf("RenderText() unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "No findings.") {
		t.Errorf("output = %q, want it to mention there are no findings", buf.String())
	}
}

func TestRenderJSONIsIndentedAndRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	report := sampleReport()
	if err := RenderJSON(&buf, report); err != nil {
		t.Fatalf("RenderJSON() unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "\n  \"") {
		t.Errorf("output does not look indented:\n%s", buf.String())
	}

	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	if decoded.Domain != report.Domain {
		t.Errorf("Domain = %q, want %q", decoded.Domain, report.Domain)
	}
	if len(decoded.Findings) != len(report.Findings) {
		t.Fatalf("Findings = %v, want %v", decoded.Findings, report.Findings)
	}
	for i := range report.Findings {
		if decoded.Findings[i] != report.Findings[i] {
			t.Errorf("Findings[%d] = %+v, want %+v", i, decoded.Findings[i], report.Findings[i])
		}
	}
	if decoded.SPF.RawRecord != report.SPF.RawRecord {
		t.Errorf("SPF.RawRecord = %q, want %q", decoded.SPF.RawRecord, report.SPF.RawRecord)
	}
	if decoded.DMARC == nil || decoded.DMARC.Policy != report.DMARC.Policy {
		t.Errorf("DMARC = %+v, want %+v", decoded.DMARC, report.DMARC)
	}
}
