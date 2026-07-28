package cidr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestAzureProviderName(t *testing.T) {
	p := NewAzureProvider()
	if got, want := p.Name(), "Azure"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestAzureProviderFetch(t *testing.T) {
	validJSON := func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"values": []map[string]any{
				{
					"name": "AzureCloud",
					"properties": map[string]any{
						"addressPrefixes": []string{"13.64.0.0/11", "2603:1000::/24"},
					},
				},
				{
					"name": "AzureCloud.eastus",
					"properties": map[string]any{
						"addressPrefixes": []string{"13.104.0.0/14"},
					},
				},
				{
					"name": "ActionGroup",
					"properties": map[string]any{
						"addressPrefixes": []string{"100.64.0.0/10"},
					},
				},
			},
		})
	}

	tests := []struct {
		name        string
		pageHandler http.HandlerFunc
		jsonHandler http.HandlerFunc
		want        []netip.Prefix
		wantErr     bool
	}{
		{
			name:        "success aggregates AzureCloud entries across families",
			jsonHandler: validJSON,
			want: []netip.Prefix{
				netip.MustParsePrefix("13.64.0.0/11"),
				netip.MustParsePrefix("2603:1000::/24"),
				netip.MustParsePrefix("13.104.0.0/14"),
			},
		},
		{
			name: "download page non-200 is an error",
			pageHandler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			},
			wantErr: true,
		},
		{
			name: "download page without a matching link is an error",
			pageHandler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html><body>no download link here</body></html>`)
			},
			wantErr: true,
		},
		{
			name: "json fetch non-200 is an error",
			jsonHandler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			},
			wantErr: true,
		},
		{
			name: "malformed json is an error",
			jsonHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("{not json"))
			},
			wantErr: true,
		},
		{
			name: "invalid address prefix is an error",
			jsonHandler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{
					"values": []map[string]any{
						{
							"name": "AzureCloud",
							"properties": map[string]any{
								"addressPrefixes": []string{"not-a-cidr"},
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
			var srv *httptest.Server
			mux := http.NewServeMux()

			mux.HandleFunc("/page", func(w http.ResponseWriter, r *http.Request) {
				if tt.pageHandler != nil {
					tt.pageHandler(w, r)
					return
				}
				fmt.Fprintf(w, `<html><body><a href="%s/files/ServiceTags_Public_20240101.json">download</a></body></html>`, srv.URL)
			})
			mux.HandleFunc("/files/ServiceTags_Public_20240101.json", func(w http.ResponseWriter, r *http.Request) {
				if tt.jsonHandler != nil {
					tt.jsonHandler(w, r)
					return
				}
				validJSON(w, r)
			})

			srv = httptest.NewServer(mux)
			defer srv.Close()

			p := &azureProvider{pageURL: srv.URL + "/page", client: srv.Client()}
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

func TestAzureProviderFetchContextCanceled(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/page", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<a href="%s/files/ServiceTags_Public_20240101.json">dl</a>`, srv.URL)
	})
	mux.HandleFunc("/files/ServiceTags_Public_20240101.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"values": []map[string]any{}})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := &azureProvider{pageURL: srv.URL + "/page", client: srv.Client()}
	if _, err := p.Fetch(ctx); err == nil {
		t.Fatal("Fetch() error = nil, want error for canceled context")
	}
}
