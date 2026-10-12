package lookup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "no such host",
			err:  &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true},
			want: true,
		},
		{
			name: "wrapped not found",
			err:  fmt.Errorf("resolve: %w", &net.DNSError{Err: "no such host", IsNotFound: true}),
			want: true,
		},
		{
			name: "timeout",
			err:  &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true},
			want: false,
		},
		{
			name: "temporary server failure",
			err:  &net.DNSError{Err: "server misbehaving", Name: "example.com", IsTemporary: true},
			want: false,
		},
		{name: "generic error", err: errors.New("SERVFAIL"), want: false},
		{name: "context canceled", err: context.Canceled, want: false},
		{name: "context deadline", err: context.DeadlineExceeded, want: false},
		{name: "nil", err: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFound(tt.err); got != tt.want {
				t.Errorf("IsNotFound(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
