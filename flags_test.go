package main

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"
	"time"
)

func TestParseFlagsDefaults(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := parseFlags([]string{"-d", "example.com"}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags() unexpected error: %v", err)
	}
	if cfg.domain != "example.com" {
		t.Errorf("domain = %q, want %q", cfg.domain, "example.com")
	}
	if cfg.cacheTTL != 24*time.Hour {
		t.Errorf("cacheTTL = %v, want 24h", cfg.cacheTTL)
	}
	if cfg.timeout != defaultTimeout {
		t.Errorf("timeout = %v, want %v", cfg.timeout, defaultTimeout)
	}
	if cfg.refreshIPs || cfg.json || cfg.noColor {
		t.Errorf("expected all boolean flags to default false, got %+v", cfg)
	}
	if len(cfg.customIPs) != 0 {
		t.Errorf("customIPs = %v, want none", cfg.customIPs)
	}
}

func TestParseFlagsLongDomainFlag(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := parseFlags([]string{"--domain", "gmail.com"}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags() unexpected error: %v", err)
	}
	if cfg.domain != "gmail.com" {
		t.Errorf("domain = %q, want %q", cfg.domain, "gmail.com")
	}
}

func TestParseFlagsRepeatableCustomIP(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := parseFlags([]string{
		"-d", "example.com",
		"-c", "10.0.0.0/8",
		"--custom-ip", "192.168.0.0/16",
	}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags() unexpected error: %v", err)
	}

	want := []string{"10.0.0.0/8", "192.168.0.0/16"}
	if len(cfg.customIPs) != len(want) {
		t.Fatalf("customIPs = %v, want %v", cfg.customIPs, want)
	}
	for i := range want {
		if cfg.customIPs[i] != want[i] {
			t.Errorf("customIPs[%d] = %q, want %q", i, cfg.customIPs[i], want[i])
		}
	}
}

func TestParseFlagsAllFlags(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := parseFlags([]string{
		"-d", "example.com",
		"--refresh-ips",
		"--cache-ttl", "1h",
		"--timeout", "5s",
		"--json",
		"--no-color",
	}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags() unexpected error: %v", err)
	}
	if !cfg.refreshIPs || !cfg.json || !cfg.noColor {
		t.Errorf("expected all boolean flags true, got %+v", cfg)
	}
	if cfg.cacheTTL != time.Hour {
		t.Errorf("cacheTTL = %v, want 1h", cfg.cacheTTL)
	}
	if cfg.timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", cfg.timeout)
	}
}

func TestParseFlagsMissingDomainIsAnError(t *testing.T) {
	var stderr bytes.Buffer
	if _, err := parseFlags([]string{}, &stderr); err == nil {
		t.Fatal("parseFlags() error = nil, want error for missing -d/--domain")
	}
}

func TestParseFlagsHelpReturnsErrHelp(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseFlags([]string{"-h"}, &stderr)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("parseFlags() error = %v, want flag.ErrHelp", err)
	}
}

func TestParseFlagsUnknownFlagIsAnError(t *testing.T) {
	var stderr bytes.Buffer
	if _, err := parseFlags([]string{"-d", "example.com", "--bogus"}, &stderr); err == nil {
		t.Fatal("parseFlags() error = nil, want error for an unknown flag")
	}
}

// TestParseFlagsHelpMergesAliasesWithoutDuplication guards against
// flag.FlagSet's default -h output, which has no notion of aliases and
// would print "-d" and "--domain" (registered separately so both
// spellings work) as two separate entries with a duplicated
// description. usageRows must list each flag pair exactly once.
func TestParseFlagsHelpMergesAliasesWithoutDuplication(t *testing.T) {
	var stderr bytes.Buffer
	parseFlags([]string{"-h"}, &stderr)
	out := stderr.String()

	if strings.Count(out, "domain to analyze") != 1 {
		t.Errorf("expected the domain flag's description exactly once, got:\n%s", out)
	}
	if strings.Count(out, "custom CIDR to flag as spoofable") != 1 {
		t.Errorf("expected the custom-ip flag's description exactly once, got:\n%s", out)
	}
	if !strings.Contains(out, "-d, --domain") {
		t.Errorf("expected the domain flag's two spellings merged onto one line, got:\n%s", out)
	}
	if !strings.Contains(out, "-c, --custom-ip") {
		t.Errorf("expected the custom-ip flag's two spellings merged onto one line, got:\n%s", out)
	}
}
