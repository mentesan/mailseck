package cidr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestOracleCloudProviderName(t *testing.T) {
	p := NewOracleCloudProvider()
	if got, want := p.Name(), "OracleCloud"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestOracleCloudProviderFetch(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    []netip.Prefix
		wantErr bool
	}{
		{
			name: "success aggregates regions across families",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{
					"regions": []map[string]any{
						{
							"region": "us-ashburn-1",
							"cidrs": []map[string]string{
								{"cidr": "129.146.0.0/16"},
								{"cidr": "2603:c020::/32"},
							},
						},
						{
							"region": "uk-london-1",
							"cidrs": []map[string]string{
								{"cidr": "140.238.0.0/15"},
							},
						},
					},
				})
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("129.146.0.0/16"),
				netip.MustParsePrefix("2603:c020::/32"),
				netip.MustParsePrefix("140.238.0.0/15"),
			},
		},
		{
			name: "empty regions",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"regions": []map[string]any{}})
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
			name: "invalid cidr is an error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{
					"regions": []map[string]any{
						{
							"region": "us-ashburn-1",
							"cidrs": []map[string]string{
								{"cidr": "not-a-cidr"},
							},
						},
					},
				})
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			p := &oracleCloudProvider{url: srv.URL, client: srv.Client()}
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

func TestOracleCloudProviderFetchContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"regions": []map[string]any{}})
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := &oracleCloudProvider{url: srv.URL, client: srv.Client()}
	if _, err := p.Fetch(ctx); err == nil {
		t.Fatal("Fetch() error = nil, want error for canceled context")
	}
}
