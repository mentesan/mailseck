package main

import (
	"bytes"
	"errors"
	"testing"

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

func TestIsTolerableSPFError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "lookup limit exceeded", err: spf.ErrLookupLimitExceeded, want: true},
		{name: "cyclic reference", err: spf.ErrCyclicReference, want: true},
		{name: "some other error", err: errors.New("boom"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTolerableSPFError(tt.err); got != tt.want {
				t.Errorf("isTolerableSPFError(%v) = %v, want %v", tt.err, got, tt.want)
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
	got := run([]string{}, &stdout, &stderr)
	if got != exitError {
		t.Errorf("run() = %d, want %d (exitError)", got, exitError)
	}
	if stderr.Len() == 0 {
		t.Error("expected an error message on stderr")
	}
}

func TestRunInvalidDomainReturnsExitError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"-d", "not a domain"}, &stdout, &stderr)
	if got != exitError {
		t.Errorf("run() = %d, want %d (exitError)", got, exitError)
	}
}

func TestRunHelpReturnsExitOK(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"-h"}, &stdout, &stderr)
	if got != exitOK {
		t.Errorf("run() = %d, want %d (exitOK)", got, exitOK)
	}
}
