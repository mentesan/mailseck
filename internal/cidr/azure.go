package cidr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
)

// azureDownloadPageURL is Microsoft's download page for the Azure IP
// Ranges and Service Tags (Public Cloud) document. The page itself does
// not carry a stable JSON link: the actual file is dated
// (ServiceTags_Public_<YYYYMMDD>.json) and re-uploaded weekly, so the
// real download URL has to be scraped from this page on every fetch.
const azureDownloadPageURL = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"

// azureServiceTagsURLPattern matches the ServiceTags JSON download link
// embedded in the download page. It intentionally does not pin the host:
// Microsoft has moved this file between CDN hosts before, and the
// characteristic part of the URL that has stayed constant is the
// "ServiceTags_Public_<8 digits>.json" filename.
var azureServiceTagsURLPattern = regexp.MustCompile(`https?://[^\s"'<>]+ServiceTags_Public_\d{8}\.json`)

// azureProvider fetches Azure's publicly-registrable IPv4 and IPv6 ranges
// by first scraping the current ServiceTags JSON URL off Microsoft's
// download page, then fetching that JSON.
type azureProvider struct {
	pageURL string
	client  *http.Client
}

// NewAzureProvider returns a CIDRProvider for Azure's public IPv4 ranges.
func NewAzureProvider() CIDRProvider {
	return &azureProvider{pageURL: azureDownloadPageURL, client: http.DefaultClient}
}

// Name returns the provider's identifier, used in findings and logs.
func (p *azureProvider) Name() string {
	return "Azure"
}

// azureServiceTagsJSON mirrors the fields of the ServiceTags document that
// Fetch needs; the upstream document carries additional fields, including
// per-region change numbers, that are intentionally ignored.
type azureServiceTagsJSON struct {
	Values []struct {
		Name       string `json:"name"`
		Properties struct {
			AddressPrefixes []string `json:"addressPrefixes"`
		} `json:"properties"`
	} `json:"values"`
}

// Fetch returns Azure's current set of publicly-registrable IP prefixes,
// covering both IPv4 and IPv6, aggregated across every "AzureCloud" and
// "AzureCloud.<region>" entry and deduplicated: Microsoft's own
// ServiceTags document lists every region's prefixes twice, once under
// its own "AzureCloud.<region>" tag and again under the umbrella
// "AzureCloud" tag, which is a superset of all regions combined. Without
// deduplication, roughly half of the returned prefixes would be exact
// repeats of another entry -- which also meant the same overlap could be
// reported more than once against a single SPF-permitted range.
func (p *azureProvider) Fetch(ctx context.Context) ([]netip.Prefix, error) {
	jsonURL, err := p.resolveServiceTagsURL(ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsonURL, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: build request for %s: %w", jsonURL, err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure: fetch %s: %w", jsonURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure: fetch %s: unexpected status %s", jsonURL, resp.Status)
	}

	var doc azureServiceTagsJSON
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("azure: decode response: %w", err)
	}

	seen := make(map[netip.Prefix]bool)
	var prefixes []netip.Prefix
	for _, value := range doc.Values {
		if !strings.Contains(value.Name, "AzureCloud") {
			continue
		}
		for _, raw := range value.Properties.AddressPrefixes {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("azure: parse prefix %q: %w", raw, err)
			}
			if seen[prefix] {
				continue
			}
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
	}

	return prefixes, nil
}

// resolveServiceTagsURL fetches the download page and extracts the current
// ServiceTags JSON URL. It returns an error, never a partial or guessed
// URL, whenever the page cannot be fetched or the link cannot be found.
func (p *azureProvider) resolveServiceTagsURL(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.pageURL, nil)
	if err != nil {
		return "", fmt.Errorf("azure: build request for download page: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("azure: fetch download page %s: %w", p.pageURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("azure: fetch download page %s: unexpected status %s", p.pageURL, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("azure: read download page %s: %w", p.pageURL, err)
	}

	jsonURL := azureServiceTagsURLPattern.FindString(string(body))
	if jsonURL == "" {
		return "", fmt.Errorf("azure: could not find ServiceTags JSON link on download page %s", p.pageURL)
	}

	return jsonURL, nil
}
