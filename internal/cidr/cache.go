package cidr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// DefaultCacheTTL is how long a cached fetch remains valid when
// CacheOptions.TTL is left unset.
const DefaultCacheTTL = 24 * time.Hour

// cacheDirName and cacheFileName make up the on-disk cache path, rooted
// under the OS-specific user cache directory (e.g.
// ~/Library/Caches/mailseck/cidrs.json on macOS).
const (
	cacheDirName  = "mailseck"
	cacheFileName = "cidrs.json"
)

// userCacheDir resolves the OS-specific base cache directory. It is a
// variable, rather than a direct call to os.UserCacheDir, so tests can
// redirect it without touching the real user cache directory.
var userCacheDir = os.UserCacheDir

// CacheOptions configures Cache's on-disk caching behavior.
type CacheOptions struct {
	// TTL is how long a cached fetch remains valid. Zero means
	// DefaultCacheTTL.
	TTL time.Duration

	// Refresh forces a fetch from every provider, ignoring any cached
	// result regardless of its age.
	Refresh bool
}

// cacheFile is the on-disk representation of a cached CIDR fetch.
type cacheFile struct {
	FetchedAt time.Time                 `json:"fetched_at"`
	Prefixes  map[string][]netip.Prefix `json:"prefixes"`
}

// Cache returns IP prefixes from every provider in providers, keyed by
// provider name, serving a valid on-disk cache when one exists and
// opts.Refresh is false. On a cache miss, on a stale cache, or when
// opts.Refresh is true, it calls Load and persists the result for next
// time. A failure to read or write the cache is not fatal: Cache falls
// back to Load, and a failure to persist a fresh result is only logged.
func Cache(ctx context.Context, providers ProviderList, opts CacheOptions) (map[string][]netip.Prefix, error) {
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}

	path, err := cacheFilePath()
	if err != nil {
		return nil, fmt.Errorf("cidr: locate cache directory: %w", err)
	}

	if !opts.Refresh {
		if prefixes, ok := readCache(path, ttl); ok {
			return prefixes, nil
		}
	}

	prefixes, err := Load(ctx, providers)
	if err != nil {
		return nil, err
	}

	if err := writeCache(path, prefixes); err != nil {
		slog.Warn("cidr: failed to persist cache", "path", path, "error", err)
	}

	return prefixes, nil
}

// cacheFilePath returns the path to the on-disk cache file.
func cacheFilePath() (string, error) {
	dir, err := userCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, cacheDirName, cacheFileName), nil
}

// readCache returns the cached prefixes at path if the file exists,
// decodes cleanly, and was fetched within ttl. Any failure of those
// conditions is treated as a cache miss, never an error: the cache is a
// best-effort optimization, not a correctness requirement.
func readCache(path string, ttl time.Duration) (map[string][]netip.Prefix, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	var doc cacheFile
	if err := json.NewDecoder(f).Decode(&doc); err != nil {
		return nil, false
	}

	if time.Since(doc.FetchedAt) > ttl {
		return nil, false
	}

	return doc.Prefixes, true
}

// writeCache persists prefixes to path, stamped with the current time,
// creating the parent directory if needed.
func writeCache(path string, prefixes map[string][]netip.Prefix) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}

	data, err := json.MarshalIndent(cacheFile{FetchedAt: time.Now(), Prefixes: prefixes}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode cache: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write cache file: %w", err)
	}

	return nil
}
