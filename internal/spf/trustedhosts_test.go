package spf

import "testing"

func TestIsTrustedMailHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{host: "spf.protection.outlook.com", want: true},
		{host: "SPF.PROTECTION.OUTLOOK.COM", want: true},
		{host: "_spf.google.com", want: true},
		{host: "amazonses.com", want: true},
		{host: "not-trusted.example.com", want: false},
		{host: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := isTrustedMailHost(tt.host); got != tt.want {
				t.Errorf("isTrustedMailHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}
