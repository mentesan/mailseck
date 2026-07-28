package spf

import "strings"

// trustedFirstPartyMailHosts are SPF include/redirect targets published
// directly by a major cloud provider for its own first-party mail
// service. Their address ranges are drawn from that same provider's
// public cloud IP space -- which is exactly why a naive overlap check
// against that provider's own CIDR feed would flag them -- but they are
// operated by the provider itself, not rentable by its customers.
//
// Trust is keyed by hostname, not by IP range, because a provider's
// published mail IPs change far more often than the hostname it
// publishes them under. An IP-based allowlist here needs constant
// upkeep and silently goes stale: this project's first attempt at this
// check (a short list of CIDRs copied from the reference tool) was
// already missing several of Microsoft 365's current outbound ranges
// by the time it was tested against a live domain.
var trustedFirstPartyMailHosts = map[string]string{
	"spf.protection.outlook.com": "Microsoft 365 (Exchange Online Protection)",
	"_spf.google.com":            "Google Workspace",
	"amazonses.com":              "Amazon SES",
}

// isTrustedMailHost reports whether host is a known first-party mail
// vendor hostname, matched case-insensitively since DNS names are.
func isTrustedMailHost(host string) bool {
	_, ok := trustedFirstPartyMailHosts[strings.ToLower(host)]
	return ok
}
