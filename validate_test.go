package main

import "testing"

func TestValidDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{domain: "example.com", want: true},
		{domain: "sub.example.com", want: true},
		{domain: "gmail.com", want: true},
		{domain: "my-domain.co", want: true},
		{domain: "a.b.c.example.io", want: true},

		{domain: "", want: false},
		{domain: "example", want: false},
		{domain: "-example.com", want: false},
		{domain: "example-.com", want: false},
		{domain: "exa mple.com", want: false},
		{domain: "example.c", want: false},
		{domain: "http://example.com", want: false},
		{domain: "example.com/", want: false},
		{domain: "example..com", want: false},
		{domain: "exam*ple.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := validDomain(tt.domain); got != tt.want {
				t.Errorf("validDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}
