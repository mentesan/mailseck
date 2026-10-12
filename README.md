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

When a domain's DMARC record (or its absence) falls short of a safe
minimum, the report also includes a suggested next-step record —
purely additive (e.g. adding `rua` reporting) when that's all that's
missing, or a minimal policy tightening (never a jump straight to
`p=reject`) when the current policy is weak. It always comes with a
disclaimer: it's a suggestion to review, not a directive, and mailseck
has no visibility into which of your senders are actually SPF/DKIM
aligned.

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

Releases cut with `make dist` (v1.3.0 onward) attach prebuilt binaries
for Linux, macOS and Windows, with a `SHA256SUMS` file. Check a download with
`sha256sum -c SHA256SUMS --ignore-missing` (or `shasum -a 256 -c`), and
confirm its version with `mailseck --version` or `go version -m
<binary>`.

`mailseck --version` reports the version the Go toolchain recorded at
build time: the release tag (e.g. `v1.3.0`) for a release binary or
`go install ...@v1.3.0`; a Go pseudo-version for a build between tags;
either with `+dirty` when the checkout had uncommitted changes; and
`devel` for `go run` or a build without git metadata, such as from a
source tarball.

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
| `--version`         | `false`      | Print `mailseck <version>` and exit 0; `-d` is not required           |

Exit code:

| Code | Meaning                                                                                       | Report on stdout |
| ---- | --------------------------------------------------------------------------------------------- | ---------------- |
| `0`  | Both checks completed and no `crit` finding was raised                                        | yes              |
| `1`  | Both checks completed and at least one `crit` finding was raised                              | yes              |
| `2`  | The SPF or DMARC lookup failed (timeout, `SERVFAIL`, expired `--timeout`): `status` is `error` | yes              |
| `2`  | Invalid input (missing or bad flag, invalid domain or `--custom-ip`) or a recovered panic     | no               |

A domain that publishes no SPF or DMARC record is a `crit` finding
(exit `1`), not a failed run. Exit `2` is ambiguous on its own: a script
should always read stdout, and when it holds a report, decide by each
check's `status` field rather than by the exit code. Every failed lookup
also writes one line to stderr naming the check, the name queried, and
the error; a record that is simply absent writes nothing there.

`--timeout` is one budget shared by the whole run, in order: CIDR
loading, then SPF (including its include/redirect chain), then DMARC. If
SPF uses it all, DMARC ends with `status` `error` because the deadline
expired, not because its lookup failed on its own.

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

When a domain's DMARC falls short of the safe minimum, a suggestion
block is appended after the findings:

```
Suggested DMARC record:
  v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua=mailto:dmarc-reports@example.com

  This is a suggested minimum configuration, not a directive -- confirm with whoever owns
  email security for this domain before publishing it. This suggestion also tightens
  enforcement: confirm every legitimate sending source (including any third-party service)
  is SPF- or DKIM-aligned before publishing it, or legitimate mail may be quarantined or
  rejected.
```

### Sample JSON output

```
$ mailseck -d example.com --json
```

```json
{
  "domain": "example.com",
  "tool_version": "v1.3.0",
  "spf": {
    "is_present": true,
    "status": "found",
    "error": "",
    "raw_record": "v=spf1 -all",
    "total_ips": 0,
    "total_lookups": 0,
    "has_hard_fail": true,
    "irresolvable_hosts": [],
    "overlaps": []
  },
  "dmarc": {
    "is_present": true,
    "status": "found",
    "error": "",
    "raw_record": "v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s",
    "policy": "reject",
    "subdomain_policy": "reject",
    "percentage": 100,
    "rua": [],
    "ruf": []
  },
  "findings": [
    {
      "code": "spf_record",
      "severity": "info",
      "title": "SPF record is defined",
      "detail": "Spoofed mail is somewhat prevented.",
      "items": []
    }
  ],
  "dmarc_suggestion": null
}
```

(Truncated here for brevity; the real output has one entry in
`findings` per check described above.) `tool_version` is the version of
the mailseck binary that produced the report, the same value
`--version` prints; it is always present and never empty (`devel` at
worst). `dmarc_suggestion` is an object
with `record` and `caveat` fields, as shown in the text example above,
whenever there's a suggestion to make; it's `null`, as here, when the
current DMARC record already meets the safe minimum.

`spf.status` and `dmarc.status` say whether each check could be
completed, and are what automation should branch on:

| `status`    | Meaning                                                                                      |
| ----------- | -------------------------------------------------------------------------------------------- |
| `found`     | The lookup succeeded and a valid record is published                                         |
| `not_found` | The lookup was answered and no valid record exists (also: zero or several `v=DMARC1` records) |
| `error`     | The lookup itself failed; nothing is known about the record, and `error` carries the message  |

For both `spf` and `dmarc`, these always hold:

- `is_present` is `true` exactly when `status` is `found`.
- `error` is a non-empty string exactly when `status` is `error`, and
  `""` otherwise — never `null`.
- With any `status` other than `found`, `raw_record` is `""` and every
  collection is `[]`.

A check with `status` `error` produces a single `warn` finding
(`spf_record` or `dmarc_record`, titled "... record could not be
verified") and no other finding for that check; for DMARC,
`dmarc_suggestion` is also `null`, since there is nothing known to
suggest from. An SPF record that exceeds the 10-lookup budget or has a
cyclic include/redirect chain is `found`, and gets a `crit`
`spf_analysis` finding.

Known limitation: the Go standard library resolver reports a domain
that does not exist at all (NXDOMAIN) the same way as a domain that
exists without the record (NODATA), so a non-existent domain shows up as
SPF and DMARC `not_found`, with both `crit` findings.

Every collection field is always an array, never `null` — an SPF record
with no unresolved hosts serializes `irresolvable_hosts` as `[]`, not
`null` — so a script or workflow tool never needs a special case for a
missing collection.

`code` is a short, stable identifier for the rule a finding evaluates
(e.g. `spf_overlap`, `dmarc_policy`). It stays the same regardless of
`severity` and across any future wording change to `title`/`detail`, so
automation should match on `code`, never on the English text. `items`
carries a finding's itemized detail — one line per overlapping CIDR, or
one hostname per unresolved host — instead of folding a variable-length
list into the `detail` sentence.

## Project layout

```
mailseck/
  main.go, flags.go, validate.go   // CLI entry point, flag parsing, domain validation
  internal/
    spf/          // SPF record resolution, RFC 7208 recursion, and lookup counting
    dmarc/        // DMARC record resolution and tag parsing
    cidr/         // Public cloud provider CIDR ranges, with an on-disk TTL cache
    lookup/       // DNS lookup outcome (found / not_found / error) shared by spf and dmarc
    report/       // Finding model, rule evaluation (Build), and text/JSON renderers
```

Every package has zero external dependencies — only the Go standard
library. See [PRD.md](PRD.md) §7 for the full architecture rationale.

## Development

This project uses a `Makefile` for the common tasks:

```
make check              # the delivery gate: fmt-check, vet, line-length, then test
make build              # build the mailseck binary
make test               # run the fast test suite with the race detector (no network access)
make test-integration   # also run tests that hit real DNS (see below); not part of check
make lint               # fmt-check + vet + line-length, without running tests
make fmt-check          # fail listing files gofmt would change, or if gofmt is not in PATH
make vet                # go vet ./...
make line-length        # fail listing file:line for any .go line above 120 characters
make dist               # release binaries + bin/SHA256SUMS, only at a release tag (see Releasing)
make clean              # remove the built binary
make install            # go install .
```

`make check` is the single gate a change must pass. `make test` runs
with `-race`, which needs cgo and a C compiler (on macOS, the Xcode
Command Line Tools); with `CGO_ENABLED=0` or no compiler it fails rather
than silently skipping the race detector. `line-length` counts
characters, not bytes, so a line with multibyte characters such as `§`
is measured the way an editor shows it, and a tab counts as one.

### Integration tests

A few tests are gated behind the `integration` build tag because they
resolve real DNS records for well-known domains (e.g. `gmail.com`,
`cloudflare.com`). They are excluded from `make test` and from `go test
./...` by default, and only run via:

```
make test-integration
```

## Releasing

Releases are cut by hand; `make dist` only builds, it never tags,
pushes or publishes.

```
make check
git tag -a v1.3.0 -m "v1.3.0: <summary>"
git push origin v1.3.0
make dist
gh release create v1.3.0 bin/* --verify-tag --notes-file <notes file>
```

`make dist` runs `make check` first, then refuses to build unless HEAD
is exactly at one `vMAJOR.MINOR.PATCH` tag (pre-release tags such as
`v1.3.0-rc1` are refused) and the working tree is clean, untracked
files included. It recreates `bin/` with one binary per platform in
`PLATFORMS` (`CGO_ENABLED=0`, `-trimpath`, `-ldflags="-s -w"`), checks
with `go version -m` that each one embeds exactly the tag, and writes
`bin/SHA256SUMS`.

The module path has no `/vN` suffix, so the Go toolchain only accepts
`v0.x.y` and `v1.x.y` tags as the module version: a `v2.0.0` tag would
be stamped as a pseudo-version and `make dist` would refuse it. Moving
to v2 means changing the module path to `github.com/mentesan/mailseck/v2`
first.

## Credits and license

Inspired by [Email-Spoof-Check](https://github.com/CyberCX-STA/Email-Spoof-Check)
(CyberCX, 2022); no code was copied from it — see [PRD.md](PRD.md) §1.1
for why, and for the design decisions that grew out of studying it.

BSD 3-Clause. See [LICENSE](LICENSE).
