// Package cidr provides publicly-registrable cloud provider IP ranges,
// used to detect SPF entries that overlap with rentable infrastructure.
package cidr

import (
	"context"
	"errors"
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

// Load fetches and merges IP prefixes from every provider in providers. A
// single provider's failure is not meant to abort the others; the error
// return is reserved for conditions that leave no usable result at all.
func Load(ctx context.Context, providers ProviderList) ([]netip.Prefix, error) {
	return nil, errors.New("cidr: Load not implemented")
}
