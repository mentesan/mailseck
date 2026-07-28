package cidr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
)

// gcpRangesURL is Google's published list of IP ranges used by Google
// Cloud Platform, including the subset that customers can register.
const gcpRangesURL = "https://www.gstatic.com/ipranges/cloud.json"

// gcpProvider fetches Google Cloud Platform's publicly-registrable IPv4
// and IPv6 ranges from Google's published cloud.json.
type gcpProvider struct {
	url    string
	client *http.Client
}

// NewGCPProvider returns a CIDRProvider for Google Cloud Platform's public
// IP ranges.
func NewGCPProvider() CIDRProvider {
	return &gcpProvider{url: gcpRangesURL, client: http.DefaultClient}
}

// Name returns the provider's identifier, used in findings and logs.
func (p *gcpProvider) Name() string {
	return "GCP"
}

// gcpCloudJSON mirrors the fields of cloud.json that Fetch needs; the
// upstream document carries additional fields that are intentionally
// ignored. Each entry carries at most one of IPv4Prefix or IPv6Prefix.
type gcpCloudJSON struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

// Fetch returns GCP's current set of publicly-registrable IP prefixes,
// covering both IPv4 and IPv6.
func (p *gcpProvider) Fetch(ctx context.Context) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, fmt.Errorf("gcp: build request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp: fetch %s: %w", p.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp: fetch %s: unexpected status %s", p.url, resp.Status)
	}

	var doc gcpCloudJSON
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("gcp: decode response: %w", err)
	}

	prefixes := make([]netip.Prefix, 0, len(doc.Prefixes))
	for _, entry := range doc.Prefixes {
		raw := entry.IPv4Prefix
		if raw == "" {
			raw = entry.IPv6Prefix
		}
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("gcp: parse prefix %q: %w", raw, err)
		}
		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}
