package cidr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestAWSProviderName(t *testing.T) {
	p := NewAWSProvider()
	if got, want := p.Name(), "AWS"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestAWSProviderFetch(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    []netip.Prefix
		wantErr bool
	}{
		{
			name: "success ignores non-EC2 services",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{
					"prefixes": []map[string]string{
						{"ip_prefix": "3.5.140.0/22", "service": "EC2"},
						{"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"},
						{"ip_prefix": "15.230.0.0/18", "service": "EC2"},
					},
				})
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("3.5.140.0/22"),
				netip.MustParsePrefix("15.230.0.0/18"),
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
			name: "invalid ip_prefix is an error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{
					"prefixes": []map[string]string{{"ip_prefix": "not-a-cidr", "service": "EC2"}},
				})
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			p := &awsProvider{url: srv.URL, client: srv.Client()}
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

func TestAWSProviderFetchContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"prefixes": []map[string]string{}})
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := &awsProvider{url: srv.URL, client: srv.Client()}
	if _, err := p.Fetch(ctx); err == nil {
		t.Fatal("Fetch() error = nil, want error for canceled context")
	}
}
