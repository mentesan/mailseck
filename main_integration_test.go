//go:build integration

package main

import (
	"bytes"
	"testing"
)

// TestRunIntegrationRealDomains exercises the full orchestration -
// flag parsing, cloud CIDR loading, SPF and DMARC resolution, and
// rendering - against real, well-known domains over real DNS and HTTP.
// It only runs with `go test -tags integration`, per this project's
// testing strategy (PRD.md §9), since it depends on network access and
// on these domains' records remaining roughly as they are today.
func TestRunIntegrationRealDomains(t *testing.T) {
	domains := []string{"gmail.com", "cloudflare.com"}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exitCode := run([]string{"-d", domain, "--timeout", "20s"}, &stdout, &stderr)

			if exitCode == exitError {
				t.Fatalf("run() = %d (exitError) for %s, stderr: %s", exitCode, domain, stderr.String())
			}
			if stdout.Len() == 0 {
				t.Errorf("run() produced no stdout output for %s", domain)
			}

			t.Logf("report for %s:\n%s", domain, stdout.String())
		})
	}
}

// TestRunIntegrationJSONOutput checks that --json against a real domain
// produces well-formed, non-empty JSON output and a non-error exit code.
func TestRunIntegrationJSONOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"-d", "gmail.com", "--json", "--timeout", "20s"}, &stdout, &stderr)

	if exitCode == exitError {
		t.Fatalf("run() = %d (exitError), stderr: %s", exitCode, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"domain": "gmail.com"`)) {
		t.Errorf("JSON output missing expected domain field: %s", stdout.String())
	}
}
