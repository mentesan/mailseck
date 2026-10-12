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
	"github.com/mentesan/mailseck/internal/lookup"
	"github.com/mentesan/mailseck/internal/report"
	"github.com/mentesan/mailseck/internal/spf"
)

// Exit codes, per the PRD: 0 means no critical finding, 1 means at
// least one was found, 2 means the run itself failed. A run that fails
// before analysis (bad flags, invalid domain or --custom-ip) emits no
// report; a run where the SPF or DMARC lookup failed still emits one, with
// that check's status set to "error".
const (
	exitOK       = 0
	exitCritical = 1
	exitError    = 2
)

// dependencies holds everything run reaches outside the process for, so
// tests can substitute a fake DNS resolver and fixed cloud CIDRs instead
// of touching the network or the on-disk CIDR cache.
type dependencies struct {
	resolver   spf.Resolver
	fetchCIDRs cidrFetcher
}

// cidrFetcher returns the cloud provider CIDRs to check SPF ranges
// against, keyed by provider name.
type cidrFetcher func(ctx context.Context, cfg config) (map[string][]netip.Prefix, error)

// productionDependencies returns the dependencies of a real run: the
// system DNS resolver and the cached cloud provider CIDR fetch.
func productionDependencies() dependencies {
	return dependencies{resolver: spf.NewDNSResolver(), fetchCIDRs: fetchProviderCIDRs}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, productionDependencies()))
}

// run parses flags, performs the analysis, renders the report, and
// returns the process exit code. Once the input is valid it always runs
// both the SPF and the DMARC check and always renders the report, even
// when a lookup failed. It never lets a panic escape: any unexpected
// failure is recovered, reported on stderr, and turned into exitError, so
// a bug in one code path can't crash the whole process.
func run(args []string, stdout, stderr io.Writer, deps dependencies) (exitCode int) {
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

	// --version takes precedence over everything else: the domain is
	// neither validated nor queried.
	if cfg.version {
		fmt.Fprintf(stdout, "mailseck %s\n", version())
		return exitOK
	}

	if !validDomain(cfg.domain) {
		fmt.Fprintf(stderr, "mailseck: invalid domain: %q\n", cfg.domain)
		return exitError
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	cidrs, err := loadCIDRs(ctx, cfg, deps.fetchCIDRs, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "mailseck: %v\n", err)
		return exitError
	}

	// spf.Analyze only fails for a broken record (too many lookups, or a
	// cyclic include/redirect chain): exactly the conditions the tool
	// exists to detect, so the error becomes the report's top finding.
	// Lookup failures are carried in each result's Status instead.
	spfResult, spfErr := spf.Analyze(ctx, deps.resolver, cfg.domain, cidrs)
	dmarcResult := dmarc.Analyze(ctx, cfg.domain, deps.resolver)

	rep := report.Build(cfg.domain, spfResult, dmarcResult)
	rep.ToolVersion = version()
	if spfErr != nil {
		rep.Findings = append([]report.Finding{report.SPFAnalysisFinding(spfErr)}, rep.Findings...)
	}

	reportLookupFailures(stderr, cfg.domain, rep)

	if renderErr := renderReport(stdout, rep, cfg); renderErr != nil {
		fmt.Fprintf(stderr, "mailseck: render report: %v\n", renderErr)
		return exitError
	}

	return exitCodeFor(rep)
}

// loadCIDRs loads the cloud provider CIDRs through fetch and merges in
// any --custom-ip values under the "Custom" key. A total failure to load
// provider CIDRs is not fatal to the whole run: it only means overlap
// detection finds nothing this time, so it is logged and an empty map is
// used instead of aborting.
func loadCIDRs(
	ctx context.Context, cfg config, fetch cidrFetcher, stderr io.Writer,
) (map[string][]netip.Prefix, error) {
	cidrs, err := fetch(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "mailseck: warning: could not load cloud provider CIDRs, "+
			"overlap detection will be skipped: %v\n", err)
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

// fetchProviderCIDRs returns every supported cloud provider's published
// CIDRs, served from the on-disk cache while it is fresh, per cfg.
func fetchProviderCIDRs(ctx context.Context, cfg config) (map[string][]netip.Prefix, error) {
	providers := cidr.ProviderList{
		cidr.NewGCPProvider(),
		cidr.NewAWSProvider(),
		cidr.NewAzureProvider(),
		cidr.NewDigitalOceanProvider(),
		cidr.NewOracleCloudProvider(),
	}
	return cidr.Cache(ctx, providers, cidr.CacheOptions{TTL: cfg.cacheTTL, Refresh: cfg.refreshIPs})
}

// reportLookupFailures writes one stderr line per check whose DNS lookup
// failed, naming the check, the name queried, and the error. A record
// that is simply absent is a finding, not a failure, and writes nothing.
func reportLookupFailures(stderr io.Writer, domain string, rep report.Report) {
	if rep.SPF.Status == lookup.Error {
		fmt.Fprintf(stderr, "mailseck: SPF check failed: lookup %s: %s\n", domain, rep.SPF.Error)
	}
	if rep.DMARC != nil && rep.DMARC.Status == lookup.Error {
		fmt.Fprintf(stderr, "mailseck: DMARC check failed: lookup %s: %s\n", dmarc.RecordName(domain), rep.DMARC.Error)
	}
}

// renderReport writes rep to w as JSON or text, per cfg.
func renderReport(w io.Writer, rep report.Report, cfg config) error {
	if cfg.json {
		return report.RenderJSON(w, rep)
	}
	return report.RenderText(w, rep, cfg.noColor)
}

// exitCodeFor returns exitError if the SPF or DMARC lookup failed, since
// then the report cannot vouch for the domain either way; otherwise
// exitCritical if rep contains any Crit finding, and exitOK if not.
func exitCodeFor(rep report.Report) int {
	if rep.SPF.Status == lookup.Error || (rep.DMARC != nil && rep.DMARC.Status == lookup.Error) {
		return exitError
	}
	for _, f := range rep.Findings {
		if f.Severity == report.Crit {
			return exitCritical
		}
	}
	return exitOK
}
