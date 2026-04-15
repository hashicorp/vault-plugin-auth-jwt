// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/go-jose/go-jose/v3"
	"github.com/hashicorp/cap/jwt"
)

// KeySetCache maintains a lightweight kid→KeySet index for efficient lookup.
// The actual JWKS fetching, caching, and verification is handled by CAP's KeySet.
//
// This cache only stores which key IDs (kids) are in which KeySet, avoiding
// the need to iterate through all 50 KeySets for every JWT validation.
type KeySetCache struct {
	jwksURL string
	keySet  jwt.KeySet // The CAP KeySet (e.g., RemoteKeySet) for this JWKS URL

	mu         sync.RWMutex
	cachedKids []string // Lightweight list of key IDs only
}

// NewKeySetCache creates a new JWKS cache for the given URL.
// The keySet parameter is the CAP KeySet that handles fetching and verification.
func NewKeySetCache(jwksURL string, keySet jwt.KeySet) *KeySetCache {
	return &KeySetCache{
		jwksURL:    jwksURL,
		keySet:     keySet,
		cachedKids: []string{},
	}
}

// GetCachedKids returns the currently cached key IDs without making an HTTP request.
// This is a lightweight metadata lookup for the KeySetSearcher.
func (ksc *KeySetCache) GetCachedKids() []string {
	ksc.mu.RLock()
	defer ksc.mu.RUnlock()

	// Return a copy to prevent external modification
	kids := make([]string, len(ksc.cachedKids))
	copy(kids, ksc.cachedKids)
	return kids
}

// GetKeySet returns the CAP KeySet for signature verification.
// This is the actual go-oidc RemoteKeySet that handles all JWKS fetching and verification.
func (ksc *KeySetCache) GetKeySet() jwt.KeySet {
	return ksc.keySet
}

// RefreshKeys fetches key IDs from the remote JWKS endpoint and updates the kid cache.
// This is a lightweight operation that only stores key IDs, not full keys.
// The actual key fetching and caching is handled by the CAP KeySet.
func (ksc *KeySetCache) RefreshKeys(ctx context.Context) error {
	kids, err := ksc.fetchKids()
	if err != nil {
		return err
	}

	ksc.mu.Lock()
	ksc.cachedKids = kids
	ksc.mu.Unlock()

	return nil
}

// fetchKids performs a lightweight HTTP fetch to get only the key IDs from the JWKS endpoint.
// This is called by RefreshKeys and should not be called directly.
func (ksc *KeySetCache) fetchKids() ([]string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ksc.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("JWKS endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Extract only the key IDs (lightweight metadata)
	kids := make([]string, 0, len(keySet.Keys))
	for _, key := range keySet.Keys {
		if key.KeyID != "" {
			kids = append(kids, key.KeyID)
		}
	}

	return kids, nil
}

// GetJWKSURL returns the JWKS URL associated with this cache.
func (ksc *KeySetCache) GetJWKSURL() string {
	return ksc.jwksURL
}

// findKeySetByKid locates the appropriate KeySet for the given kid using a two-phase approach:
//
// Phase 1: Check all caches for the requested kid (no HTTP requests, ~10ms)
// Phase 2: If not found, refresh all caches in parallel (~200ms) and retry
//
// This enables fast lookups when caches are warm while handling cache misses efficiently.
func (b *jwtAuthBackend) findKeySetByKid(ctx context.Context, keyID string) (jwt.KeySet, error) {
	if keyID == "" {
		return nil, fmt.Errorf("keyID must not be empty")
	}

	// Safely snapshot the keySetCaches slice to prevent race with reset()
	b.l.RLock()
	caches := b.keySetCaches
	b.l.RUnlock()

	if len(caches) == 0 {
		return nil, fmt.Errorf("no key set caches configured")
	}

	// Phase 1: Fast path - check if any cache already has this kid
	keySet := findKeySetWithKid(caches, keyID)
	if keySet != nil {
		return keySet, nil
	}

	// Phase 2: Cache miss - refresh all caches in parallel and retry
	if err := b.refreshAllKeySetCaches(ctx, caches); err != nil {
		return nil, fmt.Errorf("failed to refresh JWKS caches: %w", err)
	}

	keySet = findKeySetWithKid(caches, keyID)
	if keySet != nil {
		return keySet, nil
	}

	return nil, fmt.Errorf("no key found with kid %s in any JWKS endpoint", keyID)
}

// findKeySetWithKid performs a lightweight kid lookup across all caches.
// Returns the CAP KeySet that contains the kid, or nil if not found.
func findKeySetWithKid(caches []*KeySetCache, keyID string) jwt.KeySet {
	for _, cache := range caches {
		kids := cache.GetCachedKids()

		for _, kid := range kids {
			if kid == keyID {
				return cache.GetKeySet()
			}
		}
	}

	return nil
}

// refreshAllKeySetCaches refreshes kid metadata for all JWKS URLs in parallel.
// Errors are logged but not returned since partial success is acceptable.
func (b *jwtAuthBackend) refreshAllKeySetCaches(ctx context.Context, caches []*KeySetCache) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(caches))

	for _, cache := range caches {
		wg.Add(1)
		go func(ksc *KeySetCache) {
			defer wg.Done()

			err := ksc.RefreshKeys(ctx)
			if err != nil {
				errChan <- fmt.Errorf("failed to refresh %s: %w", ksc.GetJWKSURL(), err)
			}
		}(cache)
	}

	wg.Wait()
	close(errChan)

	// Log errors but don't fail - partial success is acceptable
	for err := range errChan {
		b.Logger().Warn("error refreshing JWKS kid cache", "error", err)
	}

	return nil
}

// initializeKeySetCaches creates KeySetCache instances for all JWKS URLs.
// This is used both for pre-warming caches during config write and as a
// fallback during validator initialization (e.g., after Vault restart).
func (b *jwtAuthBackend) initializeKeySetCaches(pairs []*JWKSPair) error {
	b.keySetCaches = make([]*KeySetCache, 0, len(pairs))
	for _, p := range pairs {
		// Create a CAP KeySet (RemoteKeySet) for this JWKS URL
		// This handles all the actual fetching, caching, and verification
		keySet, err := jwt.NewJSONWebKeySet(b.providerCtx, p.JWKSUrl, p.JWKSCAPEM)
		if err != nil {
			return fmt.Errorf("failed to create KeySet for %s: %w", p.JWKSUrl, err)
		}

		// Our cache is just a lightweight kid→KeySet index
		ksc := NewKeySetCache(p.JWKSUrl, keySet)
		b.keySetCaches = append(b.keySetCaches, ksc)
	}
	return nil
}

// prewarmMultiJWKSCaches asynchronously fetches and caches keys from all JWKS URLs.
// This is called in a goroutine during config write to ensure caches are warm
// by the time users authenticate, avoiding cold-start latency.
//
// The pre-warming happens in parallel for all JWKS URLs to minimize total time.
func (b *jwtAuthBackend) prewarmMultiJWKSCaches(pairs []*JWKSPair) {
	b.l.Lock()

	// Always reinitialize to avoid duplicates / stale entries
	if err := b.initializeKeySetCaches(pairs); err != nil {
		b.Logger().Error("failed to initialize key set caches", "error", err)
		b.l.Unlock()
		return
	}

	b.l.Unlock() // release lock before network calls

	// Warm caches in parallel
	for _, ksc := range b.keySetCaches {
		go func(cache *KeySetCache, url string) {
			// Use background context for pre-warming since we don't want to cancel it
			ctx := context.Background()
			if err := cache.RefreshKeys(ctx); err != nil {
				b.Logger().Warn("failed to pre-warm JWKS cache", "url", url, "error", err)
			} else {
				b.Logger().Debug("successfully pre-warmed JWKS cache", "url", url)
			}
		}(ksc, ksc.GetJWKSURL())
	}
}

// jwtValidatorForMultiJWKS creates a validator for MultiJWKS using CAP's KeySetSearcher callback.
// CAP extracts the kid from the JWT and calls our callback to find the correct KeySet.
// This keeps all JWT parsing logic in CAP for security and consistency.
//
// Must be called with b.l lock held.
func (b *jwtAuthBackend) jwtValidatorForMultiJWKS(config *jwtConfig) (*jwt.Validator, error) {
	// Initialize caches if needed (already holding b.l lock)
	if len(b.keySetCaches) == 0 {
		pairs, err := NewJWKSPairsConfig(config)
		if err != nil {
			return nil, fmt.Errorf("error parsing JWKS pairs: %w", err)
		}
		if err := b.initializeKeySetCaches(pairs); err != nil {
			return nil, fmt.Errorf("error initializing key set caches: %w", err)
		}
	}

	// Create KeySetSearcher callback - CAP will call this with the kid from JWT.
	// Each KeySetCache has its own internal mutex for thread-safe access.
	keySetSearcher := func(ctx context.Context, keyID string) (jwt.KeySet, error) {
		return b.findKeySetByKid(ctx, keyID)
	}

	return jwt.NewValidatorWithKeySetSearcher(keySetSearcher)
}
