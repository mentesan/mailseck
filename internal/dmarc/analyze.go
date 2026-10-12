package dmarc

import (
	"context"
	"strconv"
	"strings"

	"github.com/mentesan/mailseck/internal/lookup"
	"github.com/mentesan/mailseck/internal/spf"
)

// defaultPercentage is the "pct" tag's default value per RFC 7489 §6.3,
// used whenever the tag is absent or does not parse as an integer.
const defaultPercentage = 100

// RecordName returns the DNS name a domain publishes its DMARC record
// at, "_dmarc.<domain>", per RFC 7489 §6.1.
func RecordName(domain string) string {
	return "_dmarc." + domain
}

// Analyze resolves domain's DMARC record, published at RecordName(domain),
// and parses its tags. It never fails: whether the record was found, is
// absent, or could not be looked up at all is reported in
// DMARCResult.Status (see lookup.IsNotFound for the split), so a caller
// always gets a result it can report on. A context that is already done
// counts as a failed lookup, and no query is sent.
func Analyze(ctx context.Context, domain string, resolver spf.Resolver) *DMARCResult {
	if err := ctx.Err(); err != nil {
		return failedResult(err)
	}

	txts, err := resolver.LookupTXT(ctx, RecordName(domain))
	if err != nil {
		if lookup.IsNotFound(err) {
			return absentResult()
		}
		return failedResult(err)
	}

	var record string
	matches := 0
	for _, txt := range txts {
		if len(txt) >= 8 && strings.EqualFold(txt[:8], "v=DMARC1") {
			record = txt
			matches++
		}
	}
	if matches != 1 {
		return absentResult()
	}

	tags := parseTags(record)

	result := &DMARCResult{
		IsPresent:       true,
		Status:          lookup.Found,
		RawRecord:       record,
		Policy:          tags["p"],
		SubdomainPolicy: tags["sp"],
		Percentage:      defaultPercentage,
		RUA:             splitURIs(tags["rua"]),
		RUF:             splitURIs(tags["ruf"]),
	}

	if pct, ok := tags["pct"]; ok {
		if n, err := strconv.Atoi(pct); err == nil {
			result.Percentage = n
		}
	}

	return result
}

// absentResult returns the DMARCResult for a domain with no usable
// DMARC record: Status lookup.NotFound, with RUA/RUF as non-nil empty
// slices (never null in the JSON output) rather than left at their zero
// value.
func absentResult() *DMARCResult {
	return &DMARCResult{Status: lookup.NotFound, RUA: []string{}, RUF: []string{}}
}

// failedResult returns the DMARCResult for a lookup that could not be
// completed: Status lookup.Error with err's message, and RUA/RUF as
// non-nil empty slices.
func failedResult(err error) *DMARCResult {
	return &DMARCResult{Status: lookup.Error, Error: err.Error(), RUA: []string{}, RUF: []string{}}
}

// parseTags splits a DMARC record into its tags: first by ";" into
// segments, then each segment by its first "=" into a key and value. Tag
// names are matched case-insensitively per RFC 7489 §6.4; values keep
// their original case.
func parseTags(record string) map[string]string {
	tags := make(map[string]string)
	for _, segment := range strings.Split(record, ";") {
		key, value, found := strings.Cut(strings.TrimSpace(segment), "=")
		if !found {
			continue
		}
		tags[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return tags
}

// splitURIs splits a comma-separated "rua" or "ruf" tag value into its
// individual URIs, trimming surrounding whitespace from each. It returns
// a non-nil empty slice, never nil, for an empty value, so the field
// always serializes to JSON as [] rather than null.
func splitURIs(value string) []string {
	if value == "" {
		return []string{}
	}

	parts := strings.Split(value, ",")
	uris := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		uris = append(uris, part)
	}
	return uris
}
