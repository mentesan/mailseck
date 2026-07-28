package cidr

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withTempCacheDir redirects userCacheDir to a temporary directory for the
// duration of the test, restoring the original afterwards.
func withTempCacheDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	original := userCacheDir
	userCacheDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { userCacheDir = original })
}

func TestCacheMissFetchesAndPersists(t *testing.T) {
	withTempCacheDir(t)

	provider := &fakeProvider{name: "A", prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	got, err := Cache(context.Background(), ProviderList{provider}, CacheOptions{})
	if err != nil {
		t.Fatalf("Cache() unexpected error: %v", err)
	}
	if len(got["A"]) != 1 || got["A"][0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("Cache() = %v, want A -> [10.0.0.0/8]", got)
	}
	if calls := provider.calls.Load(); calls != 1 {
		t.Fatalf("provider Fetch called %d times, want 1", calls)
	}

	path, err := cacheFilePath()
	if err != nil {
		t.Fatalf("cacheFilePath() error: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cache file not written: %v", err)
	}
}

func TestCacheHitSkipsFetch(t *testing.T) {
	withTempCacheDir(t)

	provider := &fakeProvider{name: "A", prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	providers := ProviderList{provider}

	if _, err := Cache(context.Background(), providers, CacheOptions{}); err != nil {
		t.Fatalf("first Cache() unexpected error: %v", err)
	}

	got, err := Cache(context.Background(), providers, CacheOptions{})
	if err != nil {
		t.Fatalf("second Cache() unexpected error: %v", err)
	}
	if len(got["A"]) != 1 || got["A"][0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("Cache() = %v, want A -> [10.0.0.0/8]", got)
	}
	if calls := provider.calls.Load(); calls != 1 {
		t.Fatalf("provider Fetch called %d times across two Cache() calls, want 1 (second should be a cache hit)", calls)
	}
}

func TestCacheForceRefreshBypassesFreshCache(t *testing.T) {
	withTempCacheDir(t)

	provider := &fakeProvider{name: "A", prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	providers := ProviderList{provider}

	if _, err := Cache(context.Background(), providers, CacheOptions{}); err != nil {
		t.Fatalf("first Cache() unexpected error: %v", err)
	}

	if _, err := Cache(context.Background(), providers, CacheOptions{Refresh: true}); err != nil {
		t.Fatalf("forced Cache() unexpected error: %v", err)
	}
	if calls := provider.calls.Load(); calls != 2 {
		t.Fatalf("provider Fetch called %d times, want 2 (Refresh should force a second fetch)", calls)
	}
}

func TestCacheStaleEntryRefetches(t *testing.T) {
	withTempCacheDir(t)

	path, err := cacheFilePath()
	if err != nil {
		t.Fatalf("cacheFilePath() error: %v", err)
	}
	writeRawCache(t, path, cacheFile{
		FetchedAt: time.Now().Add(-48 * time.Hour),
		Prefixes: map[string][]netip.Prefix{
			"A": {netip.MustParsePrefix("192.0.2.0/24")},
		},
	})

	provider := &fakeProvider{name: "A", prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	got, err := Cache(context.Background(), ProviderList{provider}, CacheOptions{TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("Cache() unexpected error: %v", err)
	}
	if len(got["A"]) != 1 || got["A"][0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("Cache() = %v, want the freshly-fetched prefix, not the stale cached one", got)
	}
	if calls := provider.calls.Load(); calls != 1 {
		t.Fatalf("provider Fetch called %d times, want 1 (stale cache should trigger a refetch)", calls)
	}
}

func TestCacheCorruptedFileTreatedAsMiss(t *testing.T) {
	withTempCacheDir(t)

	path, err := cacheFilePath()
	if err != nil {
		t.Fatalf("cacheFilePath() error: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	provider := &fakeProvider{name: "A", prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	got, err := Cache(context.Background(), ProviderList{provider}, CacheOptions{})
	if err != nil {
		t.Fatalf("Cache() unexpected error: %v", err)
	}
	if len(got["A"]) != 1 || got["A"][0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("Cache() = %v, want A -> [10.0.0.0/8]", got)
	}
}

func TestCacheAllProvidersFailWithoutCacheIsAnError(t *testing.T) {
	withTempCacheDir(t)

	provider := &fakeProvider{name: "A", err: errors.New("boom")}
	if _, err := Cache(context.Background(), ProviderList{provider}, CacheOptions{}); err == nil {
		t.Fatal("Cache() error = nil, want error when every provider fails and no cache exists")
	}
}

// writeRawCache encodes doc directly to path, bypassing Cache/writeCache,
// so tests can set up cache files with an arbitrary FetchedAt.
func writeRawCache(t *testing.T, path string, doc cacheFile) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
}
