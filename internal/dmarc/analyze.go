package dmarc

import (
	"context"
	"strconv"
	"strings"

	"github.com/mentesan/mailseck/internal/spf"
)

// defaultPercentage is the "pct" tag's default value per RFC 7489 §6.3,
// used whenever the tag is absent or does not parse as an integer.
const defaultPercentage = 100

// Analyze resolves domain's DMARC record, published at
// "_dmarc.<domain>", and parses its tags. A domain that publishes no
// record, publishes more than one candidate record (invalid per RFC 7489
// §6.6.3), or whose DNS lookup simply fails is not treated as an error:
// DMARCResult.IsPresent is false in all three cases, since the ordinary
// way a domain signals "I have no DMARC" is for that subdomain not to
// exist at all. This deliberately differs from how this project's spf
// package treats its own root lookup failure as fatal: _dmarc.<domain>
// is a purpose-built subdomain that simply not existing is the expected,
// overwhelmingly common case, not a sign of a broken domain.
func Analyze(ctx context.Context, domain string, resolver spf.Resolver) (*DMARCResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	txts, err := resolver.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		return absentResult(), nil
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
		return absentResult(), nil
	}

	tags := parseTags(record)

	result := &DMARCResult{
		IsPresent:       true,
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

	return result, nil
}

// absentResult returns the DMARCResult for a domain with no usable
// DMARC record: IsPresent false, with RUA/RUF as non-nil empty slices
// (never null in the JSON output) rather than left at their zero value.
func absentResult() *DMARCResult {
	return &DMARCResult{IsPresent: false, RUA: []string{}, RUF: []string{}}
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
