// Package cidr provides publicly-registrable cloud provider IP ranges,
// used to detect SPF entries that overlap with rentable infrastructure.
package cidr

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
)

// CIDRProvider is a source of publicly-registrable IP prefixes for a single
// cloud platform. Each provider is queried independently so that one
// provider's failure does not prevent the others from being checked.
type CIDRProvider interface {
	// Name returns the provider's identifier, used in findings and logs.
	Name() string

	// Fetch returns the provider's current set of publicly-registrable IP
	// prefixes.
	Fetch(ctx context.Context) ([]netip.Prefix, error)
}

// ProviderList is an ordered set of CIDR providers to query together.
type ProviderList []CIDRProvider

// providerResult carries one provider's outcome back from its goroutine in
// Load.
type providerResult struct {
	name     string
	prefixes []netip.Prefix
	err      error
}

// Load fetches IP prefixes from every provider in providers concurrently,
// keyed by provider name. A provider that fails is logged as a warning and
// simply contributes no prefixes; Load only returns an error when every
// provider failed, leaving no usable result at all.
func Load(ctx context.Context, providers ProviderList) (map[string][]netip.Prefix, error) {
	results := make(chan providerResult, len(providers))
	for _, provider := range providers {
		go func(provider CIDRProvider) {
			prefixes, err := provider.Fetch(ctx)
			results <- providerResult{name: provider.Name(), prefixes: prefixes, err: err}
		}(provider)
	}

	byProvider := make(map[string][]netip.Prefix, len(providers))
	failed := 0
	for range providers {
		r := <-results
		if r.err != nil {
			slog.Warn("cidr: provider fetch failed", "provider", r.name, "error", r.err)
			failed++
			continue
		}
		byProvider[r.name] = r.prefixes
	}

	if len(providers) > 0 && failed == len(providers) {
		return nil, errors.New("cidr: all providers failed")
	}

	return byProvider, nil
}
