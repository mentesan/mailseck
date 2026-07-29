package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mentesan/mailseck/internal/cidr"
)

// defaultTimeout is the overall deadline for one mailseck run: CIDR
// loading, SPF resolution (including its recursive chain), and DMARC
// resolution all share this single budget.
const defaultTimeout = 30 * time.Second

// config holds the parsed command-line flags for one run.
type config struct {
	domain     string
	customIPs  []string
	refreshIPs bool
	cacheTTL   time.Duration
	timeout    time.Duration
	json       bool
	noColor    bool
}

// stringSliceFlag is a flag.Value that accumulates every occurrence of a
// repeatable flag into a slice, in the order given.
type stringSliceFlag []string

// String returns the accumulated values, comma-separated, satisfying
// flag.Value.
func (s *stringSliceFlag) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

// Set appends value to the flag's accumulated values, satisfying
// flag.Value.
func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// usageRows is the help text for each flag, short and long name merged
// onto one line. flag.FlagSet.PrintDefaults has no notion of aliases:
// since -d/--domain and -c/--custom-ip are each registered twice (once
// per name) to support both spellings, it would print every name as its
// own separate entry with a duplicated description. This table is
// printed instead; keep it in sync with the fs.StringVar/fs.Var calls
// below whenever a flag is added, renamed, or removed.
var usageRows = [][2]string{
	{"-d, --domain string", "domain to analyze (required)"},
	{"-c, --custom-ip string", "custom CIDR to flag as spoofable (repeatable)"},
	{"--refresh-ips", "force a refresh of the cached cloud provider CIDRs"},
	{"--cache-ttl duration", "validity duration of the cloud CIDR cache (default 24h)"},
	{"--timeout duration", "overall timeout for the whole analysis (default 30s)"},
	{"--json", "emit the report as JSON instead of text"},
	{"--no-color", "disable ANSI colors even on a terminal"},
}

// parseFlags parses args into a config. It returns flag.ErrHelp
// unchanged when -h/--help was requested, so callers can treat that as
// a successful exit rather than a usage error.
func parseFlags(args []string, output io.Writer) (config, error) {
	fs := flag.NewFlagSet("mailseck", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.Usage = func() {
		fmt.Fprint(output, "Usage: mailseck -d example.com [flags]\n\n")
		for _, row := range usageRows {
			fmt.Fprintf(output, "  %-24s %s\n", row[0], row[1])
		}
	}

	var cfg config
	var customIPs stringSliceFlag

	fs.StringVar(&cfg.domain, "d", "", "domain to analyze (required)")
	fs.StringVar(&cfg.domain, "domain", "", "domain to analyze (required)")
	fs.Var(&customIPs, "c", "custom CIDR to flag as spoofable (repeatable)")
	fs.Var(&customIPs, "custom-ip", "custom CIDR to flag as spoofable (repeatable)")
	fs.BoolVar(&cfg.refreshIPs, "refresh-ips", false, "force a refresh of the cached cloud provider CIDRs")
	fs.DurationVar(&cfg.cacheTTL, "cache-ttl", cidr.DefaultCacheTTL, "validity duration of the cloud CIDR cache")
	fs.DurationVar(&cfg.timeout, "timeout", defaultTimeout, "overall timeout for the whole analysis")
	fs.BoolVar(&cfg.json, "json", false, "emit the report as JSON instead of text")
	fs.BoolVar(&cfg.noColor, "no-color", false, "disable ANSI colors even on a terminal")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	cfg.customIPs = customIPs

	if cfg.domain == "" {
		return config{}, errors.New("missing required flag: -d/--domain")
	}

	return cfg, nil
}
