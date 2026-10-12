// Package lookup classifies the outcome of the DNS TXT query behind each
// mailseck check, so a record that is absent can be told apart from a
// query that could not be completed.
package lookup

import (
	"errors"
	"net"
)

// Status is the outcome of the DNS query behind one check. It has exactly
// three values, serialized verbatim in the JSON output, so automation can
// tell "the domain does not publish this record" from "the record could
// not be checked".
type Status string

const (
	// Found means the query succeeded and returned a usable record.
	Found Status = "found"

	// NotFound means the query was answered and no usable record exists:
	// the name does not exist, it has no TXT record, or none of its TXT
	// records is a valid record of the kind being checked.
	NotFound Status = "not_found"

	// Error means the query itself failed (timeout, SERVFAIL, refused,
	// canceled or expired context), so nothing is known about the record.
	Error Status = "error"
)

// IsNotFound reports whether err, returned by a DNS lookup, means the
// queried name has no record rather than that the lookup failed. The
// standard library resolver reports both NXDOMAIN and NODATA as a
// *net.DNSError with IsNotFound set and gives no way to tell them apart,
// so both count as not found; every other error, including a canceled or
// expired context, does not.
func IsNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
