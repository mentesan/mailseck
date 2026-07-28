package cidr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
)

// awsRangesURL is Amazon's published list of IP ranges used by AWS
// services, including the EC2 ranges that customers can launch instances
// into.
const awsRangesURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

// awsEC2Service is the "service" value that marks a prefix as part of the
// EC2 range, i.e. rentable by any AWS customer.
const awsEC2Service = "EC2"

// awsProvider fetches AWS's publicly-registrable EC2 IPv4 ranges from
// Amazon's published ip-ranges.json.
type awsProvider struct {
	url    string
	client *http.Client
}

// NewAWSProvider returns a CIDRProvider for AWS EC2's public IPv4 ranges.
func NewAWSProvider() CIDRProvider {
	return &awsProvider{url: awsRangesURL, client: http.DefaultClient}
}

// Name returns the provider's identifier, used in findings and logs.
func (p *awsProvider) Name() string {
	return "AWS"
}

// awsIPRangesJSON mirrors the fields of ip-ranges.json that Fetch needs;
// the upstream document carries additional fields, including a separate
// ipv6_prefixes list, that are intentionally ignored.
type awsIPRangesJSON struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"`
		Service  string `json:"service"`
	} `json:"prefixes"`
}

// Fetch returns AWS EC2's current set of publicly-registrable IPv4
// prefixes.
func (p *awsProvider) Fetch(ctx context.Context) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, fmt.Errorf("aws: build request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aws: fetch %s: %w", p.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aws: fetch %s: unexpected status %s", p.url, resp.Status)
	}

	var doc awsIPRangesJSON
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("aws: decode response: %w", err)
	}

	prefixes := make([]netip.Prefix, 0, len(doc.Prefixes))
	for _, entry := range doc.Prefixes {
		if entry.Service != awsEC2Service {
			continue
		}
		prefix, err := netip.ParsePrefix(entry.IPPrefix)
		if err != nil {
			return nil, fmt.Errorf("aws: parse prefix %q: %w", entry.IPPrefix, err)
		}
		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}
