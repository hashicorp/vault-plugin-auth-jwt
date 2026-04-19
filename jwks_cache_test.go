// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	sqjwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/hashicorp/cap/jwt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

// mockJWKSServer creates a test JWKS server with configurable kid values
type mockJWKSServer struct {
	t            *testing.T
	server       *httptest.Server
	kids         []string
	requestCount int32
	mu           sync.Mutex
}

func newMockJWKSServer(t *testing.T, kids []string) *mockJWKSServer {
	m := &mockJWKSServer{
		t:    t,
		kids: kids,
	}

	m.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&m.requestCount, 1)

		// Parse the public key
		block, _ := pem.Decode([]byte(ecdsaPubKey))
		require.NotNil(t, block, "unable to decode public key")

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		require.NoError(t, err)

		// Create JWKS with multiple keys (one for each kid)
		keys := make([]jose.JSONWebKey, 0, len(m.kids))
		for _, kid := range m.kids {
			keys = append(keys, jose.JSONWebKey{
				Key:   pub,
				KeyID: kid,
			})
		}

		jwks := jose.JSONWebKeySet{Keys: keys}
		data, err := json.Marshal(jwks)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))

	return m
}

func (m *mockJWKSServer) getRequestCount() int32 {
	return atomic.LoadInt32(&m.requestCount)
}

func (m *mockJWKSServer) resetRequestCount() {
	atomic.StoreInt32(&m.requestCount, 0)
}

func (m *mockJWKSServer) getTLSCert() (string, error) {
	cert := m.server.Certificate()
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	pemBuf := new(bytes.Buffer)
	if err := pem.Encode(pemBuf, block); err != nil {
		return "", err
	}

	return pemBuf.String(), nil
}

// createCAContext creates a context with CA-configured HTTP client for testing.
// Used by isolated JWKSCache unit tests that don't create full backend instances.
func createCAContext(ctx context.Context, caPEM string) (context.Context, error) {
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certPool}}
	tc := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	return context.WithValue(ctx, oauth2.HTTPClient, tc), nil
}

// TestJWKSCache_RefreshKeys tests the basic kid fetching and caching
func TestJWKSCache_RefreshKeys(t *testing.T) {
	srv := newMockJWKSServer(t, []string{"key-1", "key-2", "key-3"})
	defer srv.server.Close()

	cert, err := srv.getTLSCert()
	require.NoError(t, err)

	// Create a KeySet
	ctx := context.Background()
	keySet, err := jwt.NewJSONWebKeySet(ctx, srv.server.URL, cert)
	require.NoError(t, err)

	// Create context with CA-configured HTTP client
	caCtx, err := createCAContext(ctx, cert)
	require.NoError(t, err)

	// Create cache
	cache := NewJWKSCache(srv.server.URL, keySet, caCtx)

	// Initially empty
	kids := cache.GetCachedKids()
	assert.Empty(t, kids)

	// Refresh keys
	err = cache.RefreshKeys(ctx)
	require.NoError(t, err)

	// Should now have cached kids
	kids = cache.GetCachedKids()
	assert.Len(t, kids, 3)
	assert.Contains(t, kids, "key-1")
	assert.Contains(t, kids, "key-2")
	assert.Contains(t, kids, "key-3")

	// Verify request was made
	assert.Equal(t, int32(1), srv.getRequestCount())
}

// TestJWKSCache_InflightDeduplication tests that concurrent requests are deduplicated
func TestJWKSCache_InflightDeduplication(t *testing.T) {
	srv := newMockJWKSServer(t, []string{"key-1"})
	defer srv.server.Close()

	cert, err := srv.getTLSCert()
	require.NoError(t, err)

	ctx := context.Background()
	keySet, err := jwt.NewJSONWebKeySet(ctx, srv.server.URL, cert)
	require.NoError(t, err)

	// Create context with CA-configured HTTP client
	caCtx, err := createCAContext(ctx, cert)
	require.NoError(t, err)

	cache := NewJWKSCache(srv.server.URL, keySet, caCtx)

	// Launch 100 concurrent refresh requests
	var g errgroup.Group
	for i := 0; i < 100; i++ {
		g.Go(func() error {
			return cache.RefreshKeys(ctx)
		})
	}

	err = g.Wait()
	require.NoError(t, err)

	// All goroutines should have succeeded
	kids := cache.GetCachedKids()
	assert.Len(t, kids, 1)
	assert.Contains(t, kids, "key-1")

	// But only ONE HTTP request should have been made (inflight deduplication)
	assert.Equal(t, int32(1), srv.getRequestCount(), "expected only 1 HTTP request despite 100 concurrent calls")
}

// TestJWKSCache_GetCachedKids_ImmutableCopy tests that returned kids are a copy
func TestJWKSCache_GetCachedKids_ImmutableCopy(t *testing.T) {
	srv := newMockJWKSServer(t, []string{"key-1", "key-2"})
	defer srv.server.Close()

	cert, err := srv.getTLSCert()
	require.NoError(t, err)

	ctx := context.Background()
	keySet, err := jwt.NewJSONWebKeySet(ctx, srv.server.URL, cert)
	require.NoError(t, err)

	// Create context with CA-configured HTTP client
	caCtx, err := createCAContext(ctx, cert)
	require.NoError(t, err)

	cache := NewJWKSCache(srv.server.URL, keySet, caCtx)
	err = cache.RefreshKeys(ctx)
	require.NoError(t, err)

	// Get kids
	kids1 := cache.GetCachedKids()
	require.Len(t, kids1, 2)

	// Modify the returned slice
	kids1[0] = "modified"

	// Get kids again - should be unchanged
	kids2 := cache.GetCachedKids()
	assert.NotContains(t, kids2, "modified")
	assert.Contains(t, kids2, "key-1")
	assert.Contains(t, kids2, "key-2")
}

// TestMultiJWKS_EndToEnd_Authentication tests complete MultiJWKS login flow
func TestMultiJWKS_EndToEnd_Authentication(t *testing.T) {
	// Create 3 mock JWKS servers with different kids
	srv1 := newMockJWKSServer(t, []string{"server1-key1", "server1-key2"})
	defer srv1.server.Close()

	srv2 := newMockJWKSServer(t, []string{"server2-key1", "server2-key2"})
	defer srv2.server.Close()

	srv3 := newMockJWKSServer(t, []string{"server3-key1", "server3-key2"})
	defer srv3.server.Close()

	cert1, err := srv1.getTLSCert()
	require.NoError(t, err)
	cert2, err := srv2.getTLSCert()
	require.NoError(t, err)
	cert3, err := srv3.getTLSCert()
	require.NoError(t, err)

	// Setup backend with MultiJWKS config
	b, storage := getBackend(t)

	configData := map[string]interface{}{
		"jwks_pairs": []interface{}{
			map[string]interface{}{"jwks_url": srv1.server.URL, "jwks_ca_pem": cert1},
			map[string]interface{}{"jwks_url": srv2.server.URL, "jwks_ca_pem": cert2},
			map[string]interface{}{"jwks_url": srv3.server.URL, "jwks_ca_pem": cert3},
		},
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      configData,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("config write failed: %v", resp.Error())
	}

	// Wait for prewarm to complete deterministically
	jwtBackend := b.(*jwtAuthBackend)
	require.Eventually(t, func() bool {
		return len(jwtBackend.jwksCaches) == 3 &&
			jwtBackend.jwksCaches[0] != nil &&
			jwtBackend.jwksCaches[1] != nil &&
			jwtBackend.jwksCaches[2] != nil
	}, 2*time.Second, 50*time.Millisecond, "prewarm should initialize all caches")

	// Create role
	roleData := map[string]interface{}{
		"role_type":       "jwt",
		"bound_audiences": "https://vault.plugin.auth.jwt.test",
		"user_claim":      "https://vault/user",
		"policies":        "test",
		"groups_claim":    "https://vault/groups",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	// Test authentication with JWT from server2 (kid: server2-key1)
	cl := sqjwt.Claims{
		Subject:   "testuser",
		Issuer:    "https://team-vault.auth0.com/",
		NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
		Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
	}

	privateCl := struct {
		User   string   `json:"https://vault/user"`
		Groups []string `json:"https://vault/groups"`
	}{
		"jeff",
		[]string{"foo", "bar"},
	}

	// Create JWT with kid header
	jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl, "server2-key1")

	// Reset request counters
	srv1.resetRequestCount()
	srv2.resetRequestCount()
	srv3.resetRequestCount()

	// Login
	loginData := map[string]interface{}{
		"role": "test-role",
		"jwt":  jwtData,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      loginData,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "login failed: %v", resp.Error())

	// Verify authentication succeeded
	assert.NotNil(t, resp.Auth)
	assert.Equal(t, "jeff", resp.Auth.Alias.Name)
	assert.Contains(t, resp.Auth.Policies, "test")

	srv1Count := srv1.getRequestCount()
	srv2Count := srv2.getRequestCount()
	srv3Count := srv3.getRequestCount()

	// Srv2 must be accessed (has the kid)
	assert.Greater(t, srv2Count, int32(0), "srv2 should be accessed (has the kid)")

	// Srv1 and srv3 should have minimal or no access if kid cache is working
	// Allow some initial requests from prewarm, but not excessive repeated fetches
	assert.LessOrEqual(t, srv1Count, int32(2), "srv1 should have minimal requests (kid not present)")
	assert.LessOrEqual(t, srv3Count, int32(2), "srv3 should have minimal requests (kid not present)")

	// Log for debugging
	t.Logf("Request counts after login - srv1: %d, srv2: %d, srv3: %d", srv1Count, srv2Count, srv3Count)
}

// TestMultiJWKS_TwoPhase_ColdCache tests behavior when kid not in cache
func TestMultiJWKS_TwoPhase_ColdCache(t *testing.T) {
	srv1 := newMockJWKSServer(t, []string{"key-alpha"})
	defer srv1.server.Close()

	srv2 := newMockJWKSServer(t, []string{"key-beta"})
	defer srv2.server.Close()

	cert1, err := srv1.getTLSCert()
	require.NoError(t, err)
	cert2, err := srv2.getTLSCert()
	require.NoError(t, err)

	b, storage := getBackend(t)

	// Configure MultiJWKS
	configData := map[string]interface{}{
		"jwks_pairs": []interface{}{
			map[string]interface{}{"jwks_url": srv1.server.URL, "jwks_ca_pem": cert1},
			map[string]interface{}{"jwks_url": srv2.server.URL, "jwks_ca_pem": cert2},
		},
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      configData,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	// Get backend and wait for prewarm to complete
	jwtBackend := b.(*jwtAuthBackend)

	// Wait for prewarm to complete before clearing caches
	// This ensures we're not racing with the prewarm goroutines
	require.Eventually(t, func() bool {
		jwtBackend.l.RLock()
		defer jwtBackend.l.RUnlock()

		// Check if all caches are warmed (have kids)
		if len(jwtBackend.jwksCaches) == 0 {
			return false
		}
		for _, cache := range jwtBackend.jwksCaches {
			if len(cache.GetCachedKids()) == 0 {
				return false
			}
		}
		return true
	}, 5*time.Second, 50*time.Millisecond, "caches should be pre-warmed")

	// NOW safe to clear caches - prewarm is complete
	jwtBackend.l.Lock()
	for _, cache := range jwtBackend.jwksCaches {
		if cache != nil {
			cache.mu.Lock()
			cache.cachedKids = nil
			cache.mu.Unlock()
		}
	}
	jwtBackend.l.Unlock()

	// Reset counters AFTER clearing to get clean measurements
	srv1.resetRequestCount()
	srv2.resetRequestCount()

	// Cold cache - kid not cached yet
	// This should trigger Phase 1 (cache miss) then Phase 2 (refresh all + retry)
	ctx := context.Background()
	keySet, err := jwtBackend.findKeySetByKid(ctx, "key-beta")

	require.NoError(t, err)
	require.NotNil(t, keySet)

	// Verify both servers were refreshed (Phase 2)
	assert.Greater(t, srv1.getRequestCount(), int32(0), "srv1 should be refreshed")
	assert.Greater(t, srv2.getRequestCount(), int32(0), "srv2 should be refreshed")
}

// TestMultiJWKS_TwoPhase_WarmCache tests fast path when kid is cached
func TestMultiJWKS_TwoPhase_WarmCache(t *testing.T) {
	srv := newMockJWKSServer(t, []string{"cached-key"})
	defer srv.server.Close()

	cert, err := srv.getTLSCert()
	require.NoError(t, err)

	b, storage := getBackend(t)

	configData := map[string]interface{}{
		"jwks_pairs": []interface{}{
			map[string]interface{}{"jwks_url": srv.server.URL, "jwks_ca_pem": cert},
		},
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      configData,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	jwtBackend := b.(*jwtAuthBackend)

	// Wait for prewarm to complete deterministically
	require.Eventually(t, func() bool {
		if len(jwtBackend.jwksCaches) == 0 {
			return false
		}
		cache := jwtBackend.jwksCaches[0]
		cache.mu.Lock()
		defer cache.mu.Unlock()
		for _, kid := range cache.cachedKids {
			if kid == "cached-key" {
				return true
			}
		}
		return false
	}, 2*time.Second, 50*time.Millisecond, "prewarm should cache the kid")

	// Reset counter after prewarm
	srv.resetRequestCount()

	// Warm cache - should find kid without HTTP request
	ctx := context.Background()
	keySet, err := jwtBackend.findKeySetByKid(ctx, "cached-key")

	require.NoError(t, err)
	require.NotNil(t, keySet)

	// No new HTTP requests should be made (warm cache hit)
	assert.Equal(t, int32(0), srv.getRequestCount(), "warm cache should not make HTTP requests")
}

// TestMultiJWKS_ConcurrentLogins tests concurrent authentication with MultiJWKS
func TestMultiJWKS_ConcurrentLogins(t *testing.T) {
	srv := newMockJWKSServer(t, []string{"concurrent-key"})
	defer srv.server.Close()

	cert, err := srv.getTLSCert()
	require.NoError(t, err)

	b, storage := getBackend(t)

	// Configure
	configData := map[string]interface{}{
		"jwks_pairs": []interface{}{
			map[string]interface{}{"jwks_url": srv.server.URL, "jwks_ca_pem": cert},
		},
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      configData,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatalf("config write failed: %v", resp.Error())
	}

	// Create role
	roleData := map[string]interface{}{
		"role_type":       "jwt",
		"bound_audiences": "https://vault.plugin.auth.jwt.test",
		"user_claim":      "https://vault/user",
		"policies":        "test",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	jwtBackend := b.(*jwtAuthBackend)

	// Wait for prewarm to complete deterministically
	require.Eventually(t, func() bool {
		if len(jwtBackend.jwksCaches) == 0 {
			return false
		}
		cache := jwtBackend.jwksCaches[0]
		cache.mu.Lock()
		defer cache.mu.Unlock()
		for _, kid := range cache.cachedKids {
			if kid == "concurrent-key" {
				return true
			}
		}
		return false
	}, 2*time.Second, 50*time.Millisecond, "prewarm should cache the kid")

	// Create JWT
	cl := sqjwt.Claims{
		Subject:   "testuser",
		Issuer:    "https://team-vault.auth0.com/",
		NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
		Audience:  sqjwt.Audience{"https://vault.plugin.auth.jwt.test"},
	}

	privateCl := struct {
		User string `json:"https://vault/user"`
	}{"testuser"}

	jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl, "concurrent-key")

	// Reset counter
	srv.resetRequestCount()

	// Launch 50 concurrent login requests
	var g errgroup.Group
	successCount := int32(0)

	for i := 0; i < 50; i++ {
		g.Go(func() error {
			loginData := map[string]interface{}{
				"role": "test-role",
				"jwt":  jwtData,
			}

			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "login",
				Storage:   storage,
				Data:      loginData,
				Connection: &logical.Connection{
					RemoteAddr: "127.0.0.1",
				},
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil {
				return err
			}
			if resp.IsError() {
				return fmt.Errorf("login error: %v", resp.Error())
			}

			atomic.AddInt32(&successCount, 1)
			return nil
		})
	}

	err = g.Wait()
	require.NoError(t, err)

	// All logins should succeed
	assert.Equal(t, int32(50), successCount)

	t.Logf("Concurrent logins made %d HTTP requests (expected: minimal due to caching)",
		srv.getRequestCount())
}

// TestMultiJWKS_KidNotFound tests error handling when kid doesn't exist
func TestMultiJWKS_KidNotFound(t *testing.T) {
	srv := newMockJWKSServer(t, []string{"existing-key"})
	defer srv.server.Close()

	cert, err := srv.getTLSCert()
	require.NoError(t, err)

	b := &jwtAuthBackend{}
	b.providerCtx = context.Background()

	// Initialize caches
	ctx := context.Background()
	keySet, err := jwt.NewJSONWebKeySet(ctx, srv.server.URL, cert)
	require.NoError(t, err)

	// Use backend's createCAContext method
	caCtx, err := b.createCAContext(ctx, cert)
	require.NoError(t, err)

	cache := NewJWKSCache(srv.server.URL, keySet, caCtx)
	err = cache.RefreshKeys(ctx)
	require.NoError(t, err)

	b.jwksCaches = []*JWKSCache{cache}

	// Try to find non-existent kid
	keySet, err = b.findKeySetByKid(ctx, "non-existent-key")

	require.Error(t, err)
	assert.Nil(t, keySet)
	assert.Contains(t, err.Error(), "no key found with kid non-existent-key")
}

// TestMultiJWKS_EmptyKid tests error handling for empty kid
func TestMultiJWKS_EmptyKid(t *testing.T) {
	b := &jwtAuthBackend{}

	ctx := context.Background()
	keySet, err := b.findKeySetByKid(ctx, "")

	require.Error(t, err)
	assert.Nil(t, keySet)
	assert.Contains(t, err.Error(), "keyID must not be empty")
}

// TestMultiJWKS_ConfigReset tests that caches are cleared on config change
func TestMultiJWKS_ConfigReset(t *testing.T) {
	srv := newMockJWKSServer(t, []string{"key-1"})
	defer srv.server.Close()

	cert, err := srv.getTLSCert()
	require.NoError(t, err)

	b, storage := getBackend(t)

	// Initial config
	configData := map[string]interface{}{
		"jwks_pairs": []interface{}{
			map[string]interface{}{"jwks_url": srv.server.URL, "jwks_ca_pem": cert},
		},
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      configData,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())

	time.Sleep(100 * time.Millisecond)

	// Verify caches exist
	jwtBackend := b.(*jwtAuthBackend)
	jwtBackend.l.RLock()
	cacheCount := len(jwtBackend.jwksCaches)
	jwtBackend.l.RUnlock()
	assert.Equal(t, 1, cacheCount)

	// Reset (simulates config change)
	jwtBackend.reset()

	// Verify caches cleared
	jwtBackend.l.RLock()
	cacheCount = len(jwtBackend.jwksCaches)
	jwtBackend.l.RUnlock()
	assert.Equal(t, 0, cacheCount)
}
