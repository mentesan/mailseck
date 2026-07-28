package spf

import (
	"context"
	"net"
)

// DNSResolver is a Resolver backed by the standard library's DNS client,
// suitable for production use and for integration tests that exercise
// real DNS instead of a fake.
type DNSResolver struct {
	resolver *net.Resolver
}

// NewDNSResolver returns a DNSResolver using Go's default DNS resolver.
func NewDNSResolver() *DNSResolver {
	return &DNSResolver{resolver: net.DefaultResolver}
}

// LookupTXT returns the TXT records published for host.
func (r *DNSResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	return r.resolver.LookupTXT(ctx, host)
}
