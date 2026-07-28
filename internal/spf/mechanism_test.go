package spf

import (
	"errors"
	"testing"
)

func TestParseMechanism(t *testing.T) {
	tests := []struct {
		name      string
		part      string
		wantType  string
		wantValue string
		wantQual  byte
		wantErr   error
	}{
		{name: "include default qualifier", part: "include:example.com", wantType: "include", wantValue: "example.com", wantQual: '+'},
		{name: "include explicit pass qualifier", part: "+include:example.com", wantType: "include", wantValue: "example.com", wantQual: '+'},
		{name: "include hard fail qualifier", part: "-include:example.com", wantType: "include", wantValue: "example.com", wantQual: '-'},
		{name: "include soft fail qualifier", part: "~include:example.com", wantType: "include", wantValue: "example.com", wantQual: '~'},
		{name: "include neutral qualifier", part: "?include:example.com", wantType: "include", wantValue: "example.com", wantQual: '?'},
		{name: "ip4 with cidr", part: "ip4:192.168.0.0/24", wantType: "ip4", wantValue: "192.168.0.0/24", wantQual: '+'},
		{name: "ip4 single address", part: "ip4:192.168.0.1", wantType: "ip4", wantValue: "192.168.0.1", wantQual: '+'},
		{name: "ip6 with cidr", part: "ip6:2001:db8::/32", wantType: "ip6", wantValue: "2001:db8::/32", wantQual: '+'},
		{name: "bare ip4 without value", part: "ip4", wantType: "ip4", wantValue: "", wantQual: '+'},
		{name: "all hard fail", part: "-all", wantType: "all", wantValue: "", wantQual: '-'},
		{name: "all default qualifier", part: "all", wantType: "all", wantValue: "", wantQual: '+'},
		{name: "bare a", part: "a", wantType: "a", wantValue: "", wantQual: '+'},
		{name: "a with cidr-length only", part: "a/24", wantType: "a", wantValue: "/24", wantQual: '+'},
		{name: "a with domain", part: "a:example.com", wantType: "a", wantValue: "example.com", wantQual: '+'},
		{name: "a with domain and cidr", part: "a:example.com/24", wantType: "a", wantValue: "example.com/24", wantQual: '+'},
		{name: "bare mx", part: "mx", wantType: "mx", wantValue: "", wantQual: '+'},
		{name: "mx with domain", part: "mx:example.com", wantType: "mx", wantValue: "example.com", wantQual: '+'},
		{name: "bare ptr", part: "ptr", wantType: "ptr", wantValue: "", wantQual: '+'},
		{name: "ptr with domain", part: "ptr:example.com", wantType: "ptr", wantValue: "example.com", wantQual: '+'},
		{name: "redirect modifier", part: "redirect=example.com", wantType: "redirect", wantValue: "example.com", wantQual: '+'},
		{name: "mechanism type is case-insensitive", part: "INCLUDE:Example.com", wantType: "include", wantValue: "Example.com", wantQual: '+'},

		{name: "empty part is an error", part: "", wantErr: errEmptyMechanism},
		{name: "qualifier alone is an error", part: "-", wantErr: errEmptyMechanism},
		{name: "unknown mechanism type is an error", part: "bogus:foo", wantErr: ErrUnknownMechanism},
		{name: "exp modifier is unsupported", part: "exp=explanation.example.com", wantErr: ErrUnknownMechanism},
		{name: "macro in exists value is unsupported", part: "exists:%{i}.example.com", wantErr: ErrMacroNotSupported},
		{name: "macro in a value is unsupported", part: "a:%{d}._spf.example.com", wantErr: ErrMacroNotSupported},
		{name: "macro in ip4 value is unsupported", part: "ip4:%{i}", wantErr: ErrMacroNotSupported},
		{name: "bare percent-encoded macro in redirect is unsupported", part: "redirect=%{d}._spf.example.com", wantErr: ErrMacroNotSupported},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotValue, gotQual, err := parseMechanism(tt.part)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("parseMechanism(%q) error = %v, want error wrapping %v", tt.part, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMechanism(%q) unexpected error: %v", tt.part, err)
			}
			if gotType != tt.wantType {
				t.Errorf("parseMechanism(%q) type = %q, want %q", tt.part, gotType, tt.wantType)
			}
			if gotValue != tt.wantValue {
				t.Errorf("parseMechanism(%q) value = %q, want %q", tt.part, gotValue, tt.wantValue)
			}
			if gotQual != tt.wantQual {
				t.Errorf("parseMechanism(%q) qualifier = %q, want %q", tt.part, gotQual, tt.wantQual)
			}
		})
	}
}
