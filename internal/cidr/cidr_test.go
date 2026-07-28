package cidr

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
)

// fakeProvider is a minimal CIDRProvider for tests, returning either a
// fixed set of prefixes or a fixed error. calls counts how many times
// Fetch ran, used by cache tests to assert whether a fetch happened.
type fakeProvider struct {
	name     string
	prefixes []netip.Prefix
	err      error
	calls    atomic.Int32
}

func (p *fakeProvider) Name() string { return p.name }

func (p *fakeProvider) Fetch(ctx context.Context) ([]netip.Prefix, error) {
	p.calls.Add(1)
	if p.err != nil {
		return nil, p.err
	}
	return p.prefixes, nil
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name      string
		providers ProviderList
		want      map[string][]netip.Prefix
		wantErr   bool
	}{
		{
			name: "all providers succeed",
			providers: ProviderList{
				&fakeProvider{name: "A", prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
				&fakeProvider{name: "B", prefixes: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}},
			},
			want: map[string][]netip.Prefix{
				"A": {netip.MustParsePrefix("10.0.0.0/8")},
				"B": {netip.MustParsePrefix("172.16.0.0/12")},
			},
		},
		{
			name: "one provider fails, others still returned",
			providers: ProviderList{
				&fakeProvider{name: "A", prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
				&fakeProvider{name: "B", err: errors.New("boom")},
			},
			want: map[string][]netip.Prefix{
				"A": {netip.MustParsePrefix("10.0.0.0/8")},
			},
		},
		{
			name:      "no providers",
			providers: ProviderList{},
			want:      map[string][]netip.Prefix{},
		},
		{
			name: "every provider fails is an error",
			providers: ProviderList{
				&fakeProvider{name: "A", err: errors.New("boom")},
				&fakeProvider{name: "B", err: errors.New("also boom")},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(context.Background(), tt.providers)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("Load() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Load() = %v, want %v", got, tt.want)
			}
			for name, wantPrefixes := range tt.want {
				gotPrefixes, ok := got[name]
				if !ok {
					t.Fatalf("Load() missing provider %q", name)
				}
				if len(gotPrefixes) != len(wantPrefixes) {
					t.Fatalf("Load()[%q] = %v, want %v", name, gotPrefixes, wantPrefixes)
				}
				for i := range gotPrefixes {
					if gotPrefixes[i] != wantPrefixes[i] {
						t.Errorf("Load()[%q][%d] = %v, want %v", name, i, gotPrefixes[i], wantPrefixes[i])
					}
				}
			}
		})
	}
}
