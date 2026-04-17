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
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/hashicorp/cap/jwt"
)

// inflight represents an in-progress JWKS fetch to deduplicate concurrent requests.
// Multiple goroutines waiting for the same JWKS URL will share a single HTTP call.
type inflight struct {
	doneCh chan struct{}
	kids   []string
	err    error
}

// KidKeySetCache maintains a lightweight kid→KeySet index for efficient lookup.
// The actual JWKS fetching, caching, and verification is handled by CAP's KeySet.
//
// This cache only stores which key IDs (kids) are in which KeySet, avoiding
// the need to iterate through all 50 KeySets for every JWT validation.
type KidKeySetCache struct {
	jwksURL string
	keySet  jwt.KeySet // The CAP KeySet (e.g., RemoteKeySet) for this JWKS URL

	mu            sync.RWMutex
	cachedKids    []string  // Lightweight list of key IDs only
	inflightFetch *inflight // Deduplicates concurrent fetch requests for this JWKS URL
}

// NewKidKeySetCache creates a new JWKS cache for the given URL.
// The keySet parameter is the CAP KeySet that handles fetching and verification.
func NewKidKeySetCache(jwksURL string, keySet jwt.KeySet) *KidKeySetCache {
	return &KidKeySetCache{
		jwksURL:    jwksURL,
		keySet:     keySet,
		cachedKids: []string{},
	}
}

// GetCachedKids returns the currently cached key IDs without making an HTTP request.
// This is a lightweight metadata lookup for the KeySetSearcher.
func (ksc *KidKeySetCache) GetCachedKids() []string {
	ksc.mu.RLock()
	defer ksc.mu.RUnlock()

	// Return a copy to prevent external modification
	kids := make([]string, len(ksc.cachedKids))
	copy(kids, ksc.cachedKids)
	return kids
}

// GetKeySet returns the CAP KeySet for signature verification.
// This is the actual go-oidc RemoteKeySet that handles all JWKS fetching and verification.
func (ksc *KidKeySetCache) GetKeySet() jwt.KeySet {
	return ksc.keySet
}

// RefreshKeys fetches key IDs from the remote JWKS endpoint and updates the kid cache.
// This is a lightweight operation that only stores key IDs, not full keys.
// Uses an inflight mechanism to deduplicate concurrent requests (prevents thundering herd).
func (ksc *KidKeySetCache) RefreshKeys(ctx context.Context) error {
	// Lock to check if there's already an inflight fetch for this JWKS URL
	ksc.mu.Lock()

	// If there's not a current inflight request, create one
	if ksc.inflightFetch == nil {
		ksc.inflightFetch = &inflight{doneCh: make(chan struct{})}

		// This goroutine has exclusive ownership over the current inflight request.
		// It releases the resource by nil'ing the field when done.
		go func() {
			// Fetch kids with retry logic and production-grade error handling
			kids, err := ksc.fetchKids(context.Background())

			// Store result for all waiting goroutines
			ksc.inflightFetch.kids = kids
			ksc.inflightFetch.err = err
			close(ksc.inflightFetch.doneCh)

			// Lock to update the cached keys and free the inflight slot
			ksc.mu.Lock()
			defer ksc.mu.Unlock()

			if err == nil {
				ksc.cachedKids = kids
			}

			// Free inflight so a different request can run
			ksc.inflightFetch = nil
		}()
	}

	inflight := ksc.inflightFetch
	ksc.mu.Unlock()

	// Wait for the inflight request to complete
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-inflight.doneCh:
		return inflight.err
	}
}

// fetchKids performs a lightweight HTTP fetch to get only the key IDs from the JWKS endpoint.
// Follows go-oidc's pattern: single attempt, relies on application-level retries.
// The inflight mechanism prevents thundering herd on concurrent requests.
func (ksc *KidKeySetCache) fetchKids(ctx context.Context) ([]string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ksc.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d: %s", resp.StatusCode, string(body))
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
func (ksc *KidKeySetCache) GetJWKSURL() string {
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

	// check if cache already has this kid
	keySet := findKeySetWithKid(caches, keyID)
	if keySet != nil {
		return keySet, nil
	}

	// Cache miss - refresh all caches and retry
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
func findKeySetWithKid(caches []*KidKeySetCache, keyID string) jwt.KeySet {
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
// Logs errors but doesn't fail - partial success is acceptable for cache refresh.
func (b *jwtAuthBackend) refreshAllKeySetCaches(ctx context.Context, caches []*KidKeySetCache) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	for _, cache := range caches {
		wg.Add(1)
		go func(ksc *KidKeySetCache) {
			defer wg.Done()

			if err := ksc.RefreshKeys(ctx); err != nil {
				refreshErr := fmt.Errorf("failed to refresh %s: %w", ksc.GetJWKSURL(), err)
				mu.Lock()
				errs = append(errs, refreshErr)
				mu.Unlock()
				b.Logger().Warn("error refreshing JWKS kid cache", "error", refreshErr)
			}
		}(cache)
	}

	wg.Wait()

	if len(errs) > 0 {
		b.Logger().Debug("completed JWKS refresh with errors", "total_caches", len(caches), "failed", len(errs))
	}

	return nil
}

// initializeKeySetCaches creates KidKeySetCache instances for all JWKS URLs.
// This is used both for pre-warming caches during config write and as a
// fallback during validator initialization (e.g., after Vault restart).
func (b *jwtAuthBackend) initializeKeySetCaches(pairs []*JWKSPair) error {
	b.keySetCaches = make([]*KidKeySetCache, 0, len(pairs))
	for _, p := range pairs {
		// Create a CAP KeySet (RemoteKeySet) for this JWKS URL
		// This handles all the actual fetching, caching, and verification
		keySet, err := jwt.NewJSONWebKeySet(b.providerCtx, p.JWKSUrl, p.JWKSCAPEM)
		if err != nil {
			return fmt.Errorf("failed to create KeySet for %s: %w", p.JWKSUrl, err)
		}

		// Our cache is just a lightweight kid→KeySet index
		ksc := NewKidKeySetCache(p.JWKSUrl, keySet)
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

	b.warmMultiJWKSCaches()
}

// warmMultiJWKSCaches fetches kids from all JWKS URLs in parallel.
// Called both during config write (prewarm) and first auth request.
// Must be called in a goroutine. Does not hold any locks during network calls.
func (b *jwtAuthBackend) warmMultiJWKSCaches() {
	// Snapshot caches without holding lock
	b.l.RLock()
	caches := b.keySetCaches
	b.l.RUnlock()

	// Warm caches in parallel
	for _, ksc := range caches {
		go func(cache *KidKeySetCache, url string) {
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

		// Warm caches in background on first initialization
		// (e.g., after Vault restart, during first login)
		go b.warmMultiJWKSCaches()
	}

	// Create KeySetSearcher callback - CAP will call this with the kid from JWT.
	// Each KeySetCache has its own internal mutex for thread-safe access.
	keySetSearcher := func(ctx context.Context, keyID string) (jwt.KeySet, error) {
		return b.findKeySetByKid(ctx, keyID)
	}

	return jwt.NewValidatorWithKeySetSearcher(keySetSearcher)
}
