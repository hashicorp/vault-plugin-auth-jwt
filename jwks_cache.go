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
	"golang.org/x/oauth2"
)

// JWKSCache maintains a lightweight kid to KeySet cache for efficient lookup.
type JWKSCache struct {
	jwksURL string
	keySet  jwt.KeySet // The KeySet for this JWKS URL
	ctx     context.Context

	mu            sync.RWMutex
	cachedKids    []string  // Lightweight list of key IDs only
	inflightFetch *inflight // Deduplicates concurrent fetch requests for this JWKS URL
}

// inflight represents an in-progress JWKS fetch to deduplicate concurrent requests.
// Multiple goroutines waiting for the same JWKS URL will share a single HTTP call.
type inflight struct {
	doneCh chan struct{}
	kids   []string
	err    error
}

// NewJWKSCache creates a new JWKS cache for the given URL.
// The ctx parameter should contain an HTTP client configured with CA certs (from createCAContext).
func NewJWKSCache(jwksURL string, keySet jwt.KeySet, ctx context.Context) *JWKSCache {
	return &JWKSCache{
		jwksURL:    jwksURL,
		keySet:     keySet,
		ctx:        ctx,
		cachedKids: []string{},
	}
}

// GetCachedKids returns the currently cached key IDs without making an HTTP request.
// This is a lightweight metadata lookup for the KeySetSearcher.
func (ksc *JWKSCache) GetCachedKids() []string {
	ksc.mu.RLock()
	defer ksc.mu.RUnlock()

	// Return a copy to prevent external modification
	kids := make([]string, len(ksc.cachedKids))
	copy(kids, ksc.cachedKids)
	return kids
}

// GetKeySet returns the KeySet for signature verification.
func (ksc *JWKSCache) GetKeySet() jwt.KeySet {
	return ksc.keySet
}

// RefreshKeys fetches key IDs from the remote JWKS endpoint and updates the kid cache.
// This is a lightweight operation that only stores key IDs, not full keys.
// Uses an inflight mechanism to deduplicate concurrent requests (prevents thundering herd).
func (ksc *JWKSCache) RefreshKeys(ctx context.Context) error {
	// Lock to check if there's already an inflight fetch for this JWKS URL
	ksc.mu.Lock()

	// If there's not a current inflight request, create one
	if ksc.inflightFetch == nil {
		ksc.inflightFetch = &inflight{doneCh: make(chan struct{})}

		// This goroutine has exclusive ownership over the current inflight request.
		// It releases the resource by nil'ing the field when done.
		go func() {
			// Use detached context to prevent one caller's cancellation from affecting others
			// Add 60s timeout to prevent hanging if JWKS endpoint is unresponsive
			fetchCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			kids, err := ksc.fetchKids(fetchCtx)

			// Lock to update cache and store results BEFORE closing doneCh
			// This ensures waiters see updated cache state immediately
			ksc.mu.Lock()
			ksc.inflightFetch.kids = kids
			ksc.inflightFetch.err = err
			if err == nil {
				ksc.cachedKids = kids
			}
			doneCh := ksc.inflightFetch.doneCh
			ksc.inflightFetch = nil
			ksc.mu.Unlock()

			// Close channel AFTER updating cache to prevent race conditions
			close(doneCh)
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
// The inflight mechanism prevents thundering herd on concurrent requests.
func (ksc *JWKSCache) fetchKids(ctx context.Context) ([]string, error) {
	// Extract HTTP client from context (configured with CA certs via createCAContext)
	client := http.DefaultClient
	if c, ok := ksc.ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
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

	// Extract only the key IDs
	kids := make([]string, 0, len(keySet.Keys))
	for _, key := range keySet.Keys {
		if key.KeyID != "" {
			kids = append(kids, key.KeyID)
		}
	}

	return kids, nil
}

// GetJWKSURL returns the JWKS URL associated with this cache.
func (ksc *JWKSCache) GetJWKSURL() string {
	return ksc.jwksURL
}

// findKeySetByKid locates the appropriate KeySet for the given kid using a two-phase approach:
// Phase 1: Check all caches for the requested kid
// Phase 2: If not found, refresh all caches in parallel and retry
// This enables fast lookups when caches are warm while handling cache misses efficiently.
func (b *jwtAuthBackend) findKeySetByKid(ctx context.Context, keyID string) (jwt.KeySet, error) {
	if keyID == "" {
		return nil, fmt.Errorf("keyID must not be empty")
	}

	// Safely snapshot the jwksCaches slice to prevent race with reset()
	b.l.RLock()
	caches := b.jwksCaches
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
	// Even if refresh has partial failures, we still check if the kid was found
	// (Errors are logged in refreshAllKeySetCaches)
	b.refreshAllKeySetCaches(ctx, caches)

	keySet = findKeySetWithKid(caches, keyID)
	if keySet != nil {
		return keySet, nil
	}

	// Kid still not found after refresh
	return nil, fmt.Errorf("no key found with kid %s in any JWKS endpoint", keyID)
}

// findKeySetWithKid performs a lightweight kid lookup across all caches.
// Returns the KeySet that contains the kid, or nil if not found.
func findKeySetWithKid(caches []*JWKSCache, keyID string) jwt.KeySet {
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
func (b *jwtAuthBackend) refreshAllKeySetCaches(ctx context.Context, caches []*JWKSCache) {
	var wg sync.WaitGroup

	for _, cache := range caches {
		wg.Add(1)
		go func(ksc *JWKSCache) {
			defer wg.Done()

			if err := ksc.RefreshKeys(ctx); err != nil {
				b.Logger().Warn("error refreshing JWKS kid cache",
					"jwks_url", ksc.GetJWKSURL(),
					"error", err)
			}
		}(cache)
	}

	wg.Wait()
}

// initializeKeySetCaches creates JWKSCache instances for all JWKS URLs.
// This is used both for pre-warming caches during config write and as a
// fallback during validator initialization (e.g., after Vault restart).
func (b *jwtAuthBackend) initializeKeySetCaches(pairs []*JWKSPair) error {
	b.jwksCaches = make([]*JWKSCache, 0, len(pairs))
	for _, p := range pairs {
		// Create a KeySet for this JWKS URL
		keySet, err := jwt.NewJSONWebKeySet(b.providerCtx, p.JWKSUrl, p.JWKSCAPEM)
		if err != nil {
			return fmt.Errorf("failed to create KeySet for %s: %w", p.JWKSUrl, err)
		}

		// Create context with CA-configured HTTP client for kid fetching
		caCtx, err := b.createCAContext(b.providerCtx, p.JWKSCAPEM)
		if err != nil {
			return fmt.Errorf("failed to create CA context for %s: %w", p.JWKSUrl, err)
		}

		// cache is just a lightweight kid to KeySet
		ksc := NewJWKSCache(p.JWKSUrl, keySet, caCtx)
		b.jwksCaches = append(b.jwksCaches, ksc)
	}
	return nil
}

// prewarmMultiJWKSCaches initializes caches and triggers background warming for all JWKS URLs.
// Called synchronously during config write. The function returns quickly after launching
// background goroutines to fetch keys, ensuring the config API remains responsive.
// The background fetching happens in parallel for all JWKS URLs to minimize total time.
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

// warmMultiJWKSCaches launches background goroutines to fetch kids from all JWKS URLs.
// This is a fire-and-forget operation that returns immediately without waiting.
// Called during config write (via prewarm) and on first auth request after restart.
func (b *jwtAuthBackend) warmMultiJWKSCaches() {
	// Snapshot caches without holding lock
	b.l.RLock()
	caches := b.jwksCaches
	b.l.RUnlock()

	// Warm caches in parallel
	// RefreshKeys has built-in timeout protection via detached context
	for _, ksc := range caches {
		go func(cache *JWKSCache, url string) {
			// Use background context - RefreshKeys handles timeout internally
			ctx := context.Background()
			if err := cache.RefreshKeys(ctx); err != nil {
				b.Logger().Warn("failed to pre-warm JWKS cache", "url", url, "error", err)
			} else {
				b.Logger().Debug("successfully pre-warmed JWKS cache", "url", url)
			}
		}(ksc, ksc.GetJWKSURL())
	}
}

// jwtValidatorForMultiJWKS creates a validator for MultiJWKS using KeySetSearcher callback.
func (b *jwtAuthBackend) jwtValidatorForMultiJWKS(config *jwtConfig) (*jwt.Validator, error) {
	// Initialize caches
	if len(b.jwksCaches) == 0 {
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

	// Create KeySetSearcher callback
	keySetSearcher := func(ctx context.Context, keyID string) (jwt.KeySet, error) {
		return b.findKeySetByKid(ctx, keyID)
	}

	return jwt.NewValidatorWithKeySetSearcher(keySetSearcher)
}
