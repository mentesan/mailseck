// Command mailseck analyzes a domain's SPF and DMARC records to report
// email spoofing exposure. See PRD.md for the full requirements.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/mentesan/mailseck/internal/cidr"
	"github.com/mentesan/mailseck/internal/dmarc"
	"github.com/mentesan/mailseck/internal/report"
	"github.com/mentesan/mailseck/internal/spf"
)

// Exit codes, per the PRD: 0 means no critical finding, 1 means at
// least one was found, 2 means the run itself failed before it could
// produce a report.
const (
	exitOK       = 0
	exitCritical = 1
	exitError    = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses flags, performs the analysis, renders the report, and
// returns the process exit code. It never lets a panic escape: any
// unexpected failure is recovered, reported on stderr, and turned into
// exitError, so a bug in one code path can't crash the whole process.
func run(args []string, stdout, stderr io.Writer) (exitCode int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(stderr, "mailseck: panic recovered: %v\n", r)
			exitCode = exitError
		}
	}()

	cfg, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintf(stderr, "mailseck: %v\n", err)
		return exitError
	}

	if !validDomain(cfg.domain) {
		fmt.Fprintf(stderr, "mailseck: invalid domain: %q\n", cfg.domain)
		return exitError
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	cidrs, err := loadCIDRs(ctx, cfg, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "mailseck: %v\n", err)
		return exitError
	}

	resolver := spf.NewDNSResolver()

	spfResult, spfErr := spf.Analyze(ctx, resolver, cfg.domain, cidrs)
	if spfErr != nil && !isTolerableSPFError(spfErr) {
		fmt.Fprintf(stderr, "mailseck: analyze SPF: %v\n", spfErr)
		return exitError
	}

	dmarcResult, err := dmarc.Analyze(ctx, cfg.domain, resolver)
	if err != nil {
		fmt.Fprintf(stderr, "mailseck: analyze DMARC: %v\n", err)
		return exitError
	}

	rep := report.Build(cfg.domain, spfResult, dmarcResult)
	if spfErr != nil {
		// A tolerable SPF error still deserves top billing in the
		// report: it means the record itself is broken (a lookup-limit
		// or cyclic-reference violation), not that the tool failed.
		rep.Findings = append([]report.Finding{{
			Severity: report.Crit,
			Title:    "SPF analysis could not complete",
			Detail:   spfErr.Error(),
		}}, rep.Findings...)
	}

	if renderErr := renderReport(stdout, rep, cfg); renderErr != nil {
		fmt.Fprintf(stderr, "mailseck: render report: %v\n", renderErr)
		return exitError
	}

	return exitCodeFor(rep)
}

// loadCIDRs loads the cloud provider CIDRs (from cache or a fresh
// fetch) and merges in any --custom-ip values under the "Custom" key.
// A total failure to load provider CIDRs is not fatal to the whole run:
// it only means overlap detection finds nothing this time, so it is
// logged and an empty map is used instead of aborting.
func loadCIDRs(ctx context.Context, cfg config, stderr io.Writer) (map[string][]netip.Prefix, error) {
	providers := cidr.ProviderList{
		cidr.NewGCPProvider(),
		cidr.NewAWSProvider(),
		cidr.NewAzureProvider(),
		cidr.NewDigitalOceanProvider(),
		cidr.NewOracleCloudProvider(),
	}

	cidrs, err := cidr.Cache(ctx, providers, cidr.CacheOptions{TTL: cfg.cacheTTL, Refresh: cfg.refreshIPs})
	if err != nil {
		fmt.Fprintf(stderr, "mailseck: warning: could not load cloud provider CIDRs, overlap detection will be skipped: %v\n", err)
		cidrs = map[string][]netip.Prefix{}
	}

	for _, raw := range cfg.customIPs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid --custom-ip %q: %w", raw, err)
		}
		cidrs["Custom"] = append(cidrs["Custom"], prefix)
	}

	return cidrs, nil
}

// isTolerableSPFError reports whether err from spf.Analyze describes a
// broken SPF record (too many lookups, or a cyclic include/redirect
// chain) rather than a tool-level failure. Those are exactly the
// conditions the tool exists to detect, so they are folded into the
// report as a finding instead of aborting the run.
func isTolerableSPFError(err error) bool {
	return errors.Is(err, spf.ErrLookupLimitExceeded) || errors.Is(err, spf.ErrCyclicReference)
}

// renderReport writes rep to w as JSON or text, per cfg.
func renderReport(w io.Writer, rep report.Report, cfg config) error {
	if cfg.json {
		return report.RenderJSON(w, rep)
	}
	return report.RenderText(w, rep, cfg.noColor)
}

// exitCodeFor returns exitCritical if rep contains any Crit finding,
// exitOK otherwise.
func exitCodeFor(rep report.Report) int {
	for _, f := range rep.Findings {
		if f.Severity == report.Crit {
			return exitCritical
		}
	}
	return exitOK
}
