package cidr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestGCPProviderName(t *testing.T) {
	p := NewGCPProvider()
	if got, want := p.Name(), "GCP"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestGCPProviderFetch(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    []netip.Prefix
		wantErr bool
	}{
		{
			name: "success ignores ipv6-only entries",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{
					"prefixes": []map[string]string{
						{"ipv4Prefix": "8.8.8.0/24"},
						{"ipv6Prefix": "2001:4860::/32"},
						{"ipv4Prefix": "34.64.0.0/10"},
					},
				})
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("8.8.8.0/24"),
				netip.MustParsePrefix("34.64.0.0/10"),
			},
		},
		{
			name: "empty prefixes",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"prefixes": []map[string]string{}})
			},
			want: []netip.Prefix{},
		},
		{
			name: "non-200 status is an error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			},
			wantErr: true,
		},
		{
			name: "malformed json is an error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("{not json"))
			},
			wantErr: true,
		},
		{
			name: "invalid ipv4 prefix is an error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{
					"prefixes": []map[string]string{{"ipv4Prefix": "not-a-cidr"}},
				})
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			p := &gcpProvider{url: srv.URL, client: srv.Client()}
			got, err := p.Fetch(context.Background())

			if tt.wantErr {
				if err == nil {
					t.Fatalf("Fetch() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Fetch() unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Fetch() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Fetch()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestGCPProviderFetchContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"prefixes": []map[string]string{}})
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := &gcpProvider{url: srv.URL, client: srv.Client()}
	if _, err := p.Fetch(ctx); err == nil {
		t.Fatal("Fetch() error = nil, want error for canceled context")
	}
}
