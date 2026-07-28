package cidr

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestDigitalOceanProviderName(t *testing.T) {
	p := NewDigitalOceanProvider()
	if got, want := p.Name(), "DigitalOcean"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestDigitalOceanProviderFetch(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    []netip.Prefix
		wantErr bool
	}{
		{
			name: "success skips header, blank lines and ipv6",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ip_prefix,country_code,region,city,postal_code\n" +
					"104.131.0.0/16,US,NY,New York,10004\n" +
					"\n" +
					"2604:a880::/32,US,NY,New York,10004\n" +
					"138.197.0.0/16,US,SF,San Francisco,94103\n"))
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("104.131.0.0/16"),
				netip.MustParsePrefix("138.197.0.0/16"),
			},
		},
		{
			name: "empty body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(""))
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
			name: "invalid cidr field is an error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("abc/def,US,NY,New York,10004\n"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			p := &digitalOceanProvider{url: srv.URL, client: srv.Client()}
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

func TestDigitalOceanProviderFetchContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("104.131.0.0/16,US,NY,New York,10004\n"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := &digitalOceanProvider{url: srv.URL, client: srv.Client()}
	if _, err := p.Fetch(ctx); err == nil {
		t.Fatal("Fetch() error = nil, want error for canceled context")
	}
}
