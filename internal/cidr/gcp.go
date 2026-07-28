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
// ranges from Google's published cloud.json.
type gcpProvider struct {
	url    string
	client *http.Client
}

// NewGCPProvider returns a CIDRProvider for Google Cloud Platform's public
// IPv4 ranges.
func NewGCPProvider() CIDRProvider {
	return &gcpProvider{url: gcpRangesURL, client: http.DefaultClient}
}

// Name returns the provider's identifier, used in findings and logs.
func (p *gcpProvider) Name() string {
	return "GCP"
}

// gcpCloudJSON mirrors the fields of cloud.json that Fetch needs; the
// upstream document carries additional fields that are intentionally
// ignored.
type gcpCloudJSON struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
	} `json:"prefixes"`
}

// Fetch returns GCP's current set of publicly-registrable IPv4 prefixes.
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
		if entry.IPv4Prefix == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(entry.IPv4Prefix)
		if err != nil {
			return nil, fmt.Errorf("gcp: parse prefix %q: %w", entry.IPv4Prefix, err)
		}
		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}
