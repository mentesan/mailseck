package dmarc

import "testing"

func TestDMARCResultEffectiveSubdomainPolicy(t *testing.T) {
	tests := []struct {
		name   string
		result DMARCResult
		want   string
	}{
		{
			name:   "explicit sp tag wins",
			result: DMARCResult{Policy: "none", SubdomainPolicy: "reject"},
			want:   "reject",
		},
		{
			name:   "absent sp tag inherits p",
			result: DMARCResult{Policy: "none", SubdomainPolicy: ""},
			want:   "none",
		},
		{
			name:   "absent sp tag inherits a non-none p",
			result: DMARCResult{Policy: "reject", SubdomainPolicy: ""},
			want:   "reject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.EffectiveSubdomainPolicy(); got != tt.want {
				t.Errorf("EffectiveSubdomainPolicy() = %q, want %q", got, tt.want)
			}
		})
	}
}
