package cidr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
)

// oracleRangesURL is Oracle's published list of IP ranges used by Oracle
// Cloud Infrastructure, organized per region.
const oracleRangesURL = "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"

// oracleCloudProvider fetches Oracle Cloud Infrastructure's
// publicly-registrable IPv4 and IPv6 ranges from Oracle's published
// public_ip_ranges.json.
type oracleCloudProvider struct {
	url    string
	client *http.Client
}

// NewOracleCloudProvider returns a CIDRProvider for Oracle Cloud
// Infrastructure's public IP ranges.
func NewOracleCloudProvider() CIDRProvider {
	return &oracleCloudProvider{url: oracleRangesURL, client: http.DefaultClient}
}

// Name returns the provider's identifier, used in findings and logs.
func (p *oracleCloudProvider) Name() string {
	return "OracleCloud"
}

// oracleIPRangesJSON mirrors the fields of public_ip_ranges.json that
// Fetch needs; the upstream document carries additional fields, including
// a last-updated timestamp and per-CIDR tags, that are intentionally
// ignored.
type oracleIPRangesJSON struct {
	Regions []struct {
		CIDRs []struct {
			CIDR string `json:"cidr"`
		} `json:"cidrs"`
	} `json:"regions"`
}

// Fetch returns Oracle Cloud's current set of publicly-registrable IP
// prefixes, covering both IPv4 and IPv6, aggregated across every region.
func (p *oracleCloudProvider) Fetch(ctx context.Context) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, fmt.Errorf("oraclecloud: build request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oraclecloud: fetch %s: %w", p.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oraclecloud: fetch %s: unexpected status %s", p.url, resp.Status)
	}

	var doc oracleIPRangesJSON
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("oraclecloud: decode response: %w", err)
	}

	var prefixes []netip.Prefix
	for _, region := range doc.Regions {
		for _, entry := range region.CIDRs {
			prefix, err := netip.ParsePrefix(entry.CIDR)
			if err != nil {
				return nil, fmt.Errorf("oraclecloud: parse prefix %q: %w", entry.CIDR, err)
			}
			prefixes = append(prefixes, prefix)
		}
	}

	return prefixes, nil
}
