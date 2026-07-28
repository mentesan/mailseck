package cidr

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// doRangesURL is DigitalOcean's published geo-IP CSV export. Despite the
// "google.csv" name (an artifact of how the file is generated for Google's
// geolocation ingestion), it is DigitalOcean's own IP range list and each
// row's first field is a CIDR that customers can launch droplets into.
const doRangesURL = "https://www.digitalocean.com/geo/google.csv"

// digitalOceanProvider fetches DigitalOcean's publicly-registrable IPv4
// ranges from its geo-IP CSV export.
type digitalOceanProvider struct {
	url    string
	client *http.Client
}

// NewDigitalOceanProvider returns a CIDRProvider for DigitalOcean's public
// IPv4 ranges.
func NewDigitalOceanProvider() CIDRProvider {
	return &digitalOceanProvider{url: doRangesURL, client: http.DefaultClient}
}

// Name returns the provider's identifier, used in findings and logs.
func (p *digitalOceanProvider) Name() string {
	return "DigitalOcean"
}

// Fetch returns DigitalOcean's current set of publicly-registrable IPv4
// prefixes, read one per line from the CIDR field of the CSV export.
func (p *digitalOceanProvider) Fetch(ctx context.Context) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, fmt.Errorf("digitalocean: build request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("digitalocean: fetch %s: %w", p.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("digitalocean: fetch %s: unexpected status %s", p.url, resp.Status)
	}

	var prefixes []netip.Prefix
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "/") {
			// Skips the header row and any blank line; neither carries a
			// CIDR in its first field.
			continue
		}

		field, _, _ := strings.Cut(line, ",")
		prefix, err := netip.ParsePrefix(field)
		if err != nil {
			return nil, fmt.Errorf("digitalocean: parse prefix %q: %w", field, err)
		}
		if prefix.Addr().Is6() {
			continue
		}
		prefixes = append(prefixes, prefix)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("digitalocean: read response: %w", err)
	}

	return prefixes, nil
}
