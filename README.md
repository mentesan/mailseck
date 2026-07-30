# mailseck

A command-line tool that analyzes a domain's SPF and DMARC records to
report its exposure to email spoofing, written in Go with zero external
dependencies.

A from-scratch reimplementation of the detection logic described in
[Email-Spoof-Check](https://github.com/CyberCX-STA/Email-Spoof-Check)
(CyberCX, 2022), with several correctness and robustness fixes over the
original — see [PRD.md](PRD.md) §1.1 for the full analysis, but in short:
bounded SPF recursion (a cyclic record can no longer recurse forever),
correct RFC 7208 DNS lookup counting across `a`/`mx`/`ptr`/`exists`
alongside `include`/`redirect`, dual-stack (IPv4 **and** IPv6)
cloud-CIDR overlap detection, and DMARC subdomain-policy inheritance per
RFC 7489 §6.3.

## What it checks

**SPF**

- Whether a record is published at all, and whether it consumed more
  than the RFC 7208 §4.6.4 budget of 10 DNS lookups (which makes a
  record invalid for most mail clients).
- The total number of IPv4/IPv6 addresses the record permits as
  senders.
- Whether the record ends in a hard-fail (`-all`) directive.
- Any hostname in the include/redirect chain that failed to resolve.
- Overlap between SPF-permitted CIDRs and publicly-rentable cloud
  provider ranges (AWS, GCP, Azure, DigitalOcean, Oracle Cloud) — IP
  space an attacker could rent and use to send mail your SPF record
  would treat as authorized.

**DMARC**

- Whether a record is published at all.
- Policy (`p`) and subdomain policy (`sp`), applying RFC 7489's
  inheritance rule when `sp` is not published.
- Reporting coverage (`pct`).

Every check becomes a `Finding` ranked `info`, `warn`, or `crit`,
rendered as human-readable text or as JSON for scripts and other tools.

## Status

v1.0 complete: every package is implemented and tested, including
integration tests run against real domains over real DNS. See
[PRD.md](PRD.md) for the full requirements, architecture, and the
roadmap beyond v1.0.

## Install

Requires Go 1.26 or newer.

```
go install github.com/mentesan/mailseck@latest
```

Or build from source:

```
git clone https://github.com/mentesan/mailseck.git
cd mailseck
make build
```

## Usage

```
mailseck -d <domain> [flags]
```

| Flag                | Default      | Description                                                           |
| ------------------- | ------------ | --------------------------------------------------------------------- |
| `-d`, `--domain`    | _(required)_ | Domain to analyze                                                     |
| `-c`, `--custom-ip` |              | Custom CIDR to flag as spoofable; repeatable                          |
| `--refresh-ips`     | `false`      | Force a refresh of the cached cloud provider CIDRs, ignoring the TTL  |
| `--cache-ttl`       | `24h`        | Validity duration of the on-disk cloud CIDR cache                     |
| `--timeout`         | `30s`        | Overall timeout for the whole analysis (CIDR loading, SPF, and DMARC) |
| `--json`            | `false`      | Emit the report as JSON instead of text                               |
| `--no-color`        | `false`      | Disable ANSI colors even on a terminal                                |

Exit code: `0` if no `crit` finding was raised, `1` if at least one was,
`2` if the run itself failed (invalid input, a network/DNS failure, or
a recovered panic) before it could produce a report.

### Examples

Analyze a domain:

```
$ mailseck -d example.com
```

Machine-readable output, for scripts or CI:

```
$ mailseck -d example.com --json
```

Flag a custom IP range (e.g. your own infrastructure) as spoofable:

```
$ mailseck -d example.com -c 203.0.113.0/24 -c 198.51.100.0/24
```

Force a refresh of the cloud provider CIDR cache, bypassing its TTL:

```
$ mailseck -d example.com --refresh-ips
```

### Sample text output

```
$ mailseck -d example.com

SPF/DMARC report for example.com

[INFO] SPF record is defined
       Spoofed mail is somewhat prevented.
[INFO] 0 DNS lookup(s) were made
       More than 10, and the record would be invalid.
[INFO] All hostnames were resolved
       An irresolvable hostname may invalidate the entire record.
[INFO] '-all' directive is in use
       Mail clients know to hard fail spoofed mail.
[INFO] No common public-obtainable IP ranges exist
       No cloud provider IP ranges that would allow adversaries to bypass SPF are present in the record.
[INFO] DMARC record is defined
       SPF policy is less ambiguous.
[INFO] 100% of email is covered
       The policy is not in a phased rollout.
[INFO] DMARC policy is active
       A rejection criteria is in use or implied.
[INFO] DMARC policy is active for subdomains
       A rejection criteria is in use or implied.
```

Severity badges (`[CRIT]`, `[WARN]`, `[INFO]`) are colored on an
interactive terminal, unless `--no-color` is set or the output is
redirected or piped — in which case they render as the plain labels
shown above.

### Sample JSON output

```
$ mailseck -d example.com --json
```

```json
{
  "domain": "example.com",
  "spf": {
    "raw_record": "v=spf1 -all",
    "total_ips": 0,
    "total_lookups": 0,
    "has_hard_fail": true,
    "irresolvable_hosts": null,
    "overlaps": null
  },
  "dmarc": {
    "is_present": true,
    "raw_record": "v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s",
    "policy": "reject",
    "subdomain_policy": "reject",
    "percentage": 100,
    "rua": null,
    "ruf": null
  },
  "findings": [
    {
      "severity": "info",
      "title": "SPF record is defined",
      "detail": "Spoofed mail is somewhat prevented."
    }
  ]
}
```

(Truncated here for brevity; the real output has one entry in
`findings` per check described above.)

## Project layout

```
mailseck/
  main.go, flags.go, validate.go   // CLI entry point, flag parsing, domain validation
  internal/
    spf/          // SPF record resolution, RFC 7208 recursion, and lookup counting
    dmarc/        // DMARC record resolution and tag parsing
    cidr/         // Public cloud provider CIDR ranges, with an on-disk TTL cache
    report/       // Finding model, rule evaluation (Build), and text/JSON renderers
```

Every package has zero external dependencies — only the Go standard
library. See [PRD.md](PRD.md) §7 for the full architecture rationale.

## Development

This project uses a `Makefile` for the common tasks:

```
make build              # build the mailseck binary
make test               # run the fast test suite (no network access)
make test-integration   # also run tests that hit real DNS (see below)
make lint               # go vet + gofmt -l
make clean              # remove the built binary
make install            # go install .
```

### Integration tests

A few tests are gated behind the `integration` build tag because they
resolve real DNS records for well-known domains (e.g. `gmail.com`,
`cloudflare.com`). They are excluded from `make test` and from `go test
./...` by default, and only run via:

```
make test-integration
```

## Credits and license

Inspired by [Email-Spoof-Check](https://github.com/CyberCX-STA/Email-Spoof-Check)
(CyberCX, 2022); no code was copied from it — see [PRD.md](PRD.md) §1.1
for why, and for the design decisions that grew out of studying it.

BSD 3-Clause. See [LICENSE](LICENSE).
