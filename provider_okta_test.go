package jwtauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"golang.org/x/oauth2"
)

// ---- helpers ----------------------------------------------------------------

// newOktaTestBackend returns a minimal jwtAuthBackend suitable for unit tests.
// It does not connect to Vault storage or a real OIDC server.
func newOktaTestBackend(t *testing.T) *jwtAuthBackend {
	t.Helper()
	b := &jwtAuthBackend{
		Backend:     &framework.Backend{},
		providerCtx: context.Background(),
		cachedConfig: &jwtConfig{
			OIDCDiscoveryCAPEM: "",
		},
	}
	return b
}

// newOktaRole returns a minimal jwtRole for use in FetchGroups tests.
func newOktaRole(groupsClaim, userClaim string) *jwtRole {
	return &jwtRole{
		GroupsClaim: groupsClaim,
		UserClaim:   userClaim,
	}
}

// oktaGroupJSON returns a JSON array of Okta group objects for use in mock
// server responses.
func oktaGroupJSON(names ...string) string {
	type profile struct {
		Name string `json:"name"`
	}
	type group struct {
		ID      string  `json:"id"`
		Profile profile `json:"profile"`
	}
	groups := make([]group, len(names))
	for i, n := range names {
		groups[i] = group{ID: fmt.Sprintf("id-%d", i), Profile: profile{Name: n}}
	}
	b, _ := json.Marshal(groups)
	return string(b)
}

// buildJWTConfig builds a jwtConfig map suitable for passing to Initialize.
func buildJWTConfig(orgURL string, extra map[string]interface{}) *jwtConfig {
	pc := map[string]interface{}{
		"provider":  "okta",
		"api_token": "test-token",
	}
	if orgURL != "" {
		pc["org_url"] = orgURL
	}
	for k, v := range extra {
		pc[k] = v
	}
	return &jwtConfig{
		OIDCDiscoveryURL: "https://example.okta.com",
		ProviderConfig:   pc,
	}
}

// ---- Initialize tests -------------------------------------------------------

func TestOktaProvider_Initialize_Valid(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", nil)
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.config.OrgURL != "https://example.okta.com" {
		t.Errorf("expected org_url to be set, got %q", p.config.OrgURL)
	}
	if p.config.GroupsCap != defaultOktaGroupsCap {
		t.Errorf("expected default GroupsCap %d, got %d", defaultOktaGroupsCap, p.config.GroupsCap)
	}
	// fetch_groups not in map → should default to false
	if p.config.FetchGroups {
		t.Error("expected FetchGroups to default to false when key absent")
	}
}

func TestOktaProvider_Initialize_MissingOrgURL_DerivedFromDiscoveryURL(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("", nil) // no org_url — should be derived
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.config.OrgURL != "https://example.okta.com" {
		t.Errorf("expected org_url derived as https://example.okta.com, got %q", p.config.OrgURL)
	}
}

func TestOktaProvider_Initialize_OrgURLDerivedStripsPath(t *testing.T) {
	// Custom auth server: discovery URL has /oauth2/... path that must be stripped
	p := &OktaProvider{}
	jc := buildJWTConfig("", nil)
	jc.OIDCDiscoveryURL = "https://example.okta.com/oauth2/aus1abc123"
	delete(jc.ProviderConfig, "org_url")
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.config.OrgURL != "https://example.okta.com" {
		t.Errorf("expected path stripped, got %q", p.config.OrgURL)
	}
}

func TestOktaProvider_Initialize_MissingAPIToken_FetchGroupsTrue(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"fetch_groups": true,
	})
	delete(jc.ProviderConfig, "api_token")
	err := p.Initialize(context.Background(), jc)
	if err == nil {
		t.Fatal("expected error for missing api_token with fetch_groups=true")
	}
	if !strings.Contains(err.Error(), "api_token") {
		t.Errorf("expected error to mention api_token, got: %v", err)
	}
}

func TestOktaProvider_Initialize_MissingAPIToken_FetchGroupsFalse(t *testing.T) {
	// When fetch_groups=false, api_token is not required
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"fetch_groups": false,
	})
	delete(jc.ProviderConfig, "api_token")
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("unexpected error when fetch_groups=false and api_token missing: %v", err)
	}
}

func TestOktaProvider_Initialize_NonHTTPSOrgURL(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("http://example.okta.com", nil) // http not https
	err := p.Initialize(context.Background(), jc)
	if err == nil {
		t.Fatal("expected error for non-https org_url")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("expected error to mention https, got: %v", err)
	}
}

func TestOktaProvider_Initialize_InvalidGroupsCap(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"groups_cap": -1,
	})
	err := p.Initialize(context.Background(), jc)
	if err == nil {
		t.Fatal("expected error for negative groups_cap")
	}
}

func TestOktaProvider_Initialize_GroupsCapZeroDefaultsTo100(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"groups_cap": 0,
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.config.GroupsCap != defaultOktaGroupsCap {
		t.Errorf("expected GroupsCap=%d when 0 supplied, got %d", defaultOktaGroupsCap, p.config.GroupsCap)
	}
}

func TestOktaProvider_Initialize_InvalidGroupsFilter(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"groups_filter": "[invalid",
	})
	err := p.Initialize(context.Background(), jc)
	if err == nil {
		t.Fatal("expected error for invalid groups_filter regex")
	}
	if !strings.Contains(err.Error(), "groups_filter") {
		t.Errorf("expected error to mention groups_filter, got: %v", err)
	}
}

func TestOktaProvider_Initialize_ValidGroupsFilter(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"groups_filter": "^vault-",
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.groupsFilter == nil {
		t.Error("expected groupsFilter to be compiled")
	}
}

func TestOktaProvider_Initialize_FetchGroupsExplicitFalse(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"fetch_groups": false,
	})
	delete(jc.ProviderConfig, "api_token")
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.config.FetchGroups {
		t.Error("expected FetchGroups=false when explicitly set to false")
	}
}

// ---- SensitiveKeys tests ----------------------------------------------------

func TestOktaProvider_SensitiveKeys(t *testing.T) {
	p := &OktaProvider{}
	keys := p.SensitiveKeys()
	if len(keys) != 1 || keys[0] != "api_token" {
		t.Errorf("expected SensitiveKeys=[api_token], got %v", keys)
	}
}

// ---- FetchGroups — fetch_groups=false path ----------------------------------

func TestOktaProvider_FetchGroups_FetchGroupsDisabled_UsesToken(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"fetch_groups": false,
	})
	delete(jc.ProviderConfig, "api_token")
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	role := newOktaRole("groups", "sub")
	claims := map[string]interface{}{
		"sub":    "user@example.com",
		"groups": []interface{}{"g1", "g2", "g3"},
	}

	result, err := p.FetchGroups(context.Background(), b, claims, role, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	groups, ok := result.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", result)
	}
	if len(groups) != 3 {
		t.Errorf("expected 3 groups, got %d", len(groups))
	}
}

func TestOktaProvider_FetchGroups_FetchGroupsDisabled_MissingClaim_Error(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"fetch_groups": false,
	})
	delete(jc.ProviderConfig, "api_token")
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	role := newOktaRole("groups", "sub")
	claims := map[string]interface{}{
		"sub": "user@example.com",
		// no groups claim
	}

	_, err := p.FetchGroups(context.Background(), b, claims, role, nil)
	if err == nil {
		t.Fatal("expected error when groups claim missing and fetch_groups=false")
	}
}

func TestOktaProvider_FetchGroups_FetchGroupsDisabled_FilterApplied(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"fetch_groups":  false,
		"groups_filter": "^vault-",
	})
	delete(jc.ProviderConfig, "api_token")
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	role := newOktaRole("groups", "sub")
	claims := map[string]interface{}{
		"sub":    "user@example.com",
		"groups": []interface{}{"vault-admin", "corp-everyone", "vault-readonly"},
	}

	result, err := p.FetchGroups(context.Background(), b, claims, role, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	groups := result.([]interface{})
	if len(groups) != 2 {
		t.Errorf("expected 2 filtered groups, got %d: %v", len(groups), groups)
	}
	for _, g := range groups {
		if !strings.HasPrefix(g.(string), "vault-") {
			t.Errorf("expected only vault- groups, got %q", g)
		}
	}
}

// ---- FetchGroups — fast path (below cap, no API call) -----------------------

func TestOktaProvider_FetchGroups_FastPath_BelowCap_NoAPICall(t *testing.T) {
	// Mock server that should NOT be called
	called := false
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	p := &OktaProvider{}
	jc := buildJWTConfig(ts.URL, map[string]interface{}{
		"groups_cap":   5,
		"fetch_groups": true,
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	b.providerCtx = context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client())
	role := newOktaRole("groups", "sub")
	// 3 groups < cap of 5 → fast path
	claims := map[string]interface{}{
		"sub":    "user@example.com",
		"groups": []interface{}{"g1", "g2", "g3"},
	}

	result, err := p.FetchGroups(context.Background(), b, claims, role, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Error("API should not have been called on fast path")
	}
	_ = result
}

func TestOktaProvider_FetchGroups_FastPath_WithFilter_NoAPICall(t *testing.T) {
	called := false
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	p := &OktaProvider{}
	jc := buildJWTConfig(ts.URL, map[string]interface{}{
		"groups_cap":    5,
		"groups_filter": "^vault-",
		"fetch_groups":  true,
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	b.providerCtx = context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client())
	role := newOktaRole("groups", "sub")
	claims := map[string]interface{}{
		"sub":    "user@example.com",
		"groups": []interface{}{"vault-admin", "corp-all", "vault-readonly"},
	}

	result, err := p.FetchGroups(context.Background(), b, claims, role, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Error("API should not have been called on fast path")
	}
	groups := result.([]interface{})
	if len(groups) != 2 {
		t.Errorf("expected 2 filtered groups, got %d", len(groups))
	}
}

// ---- FetchGroups — API fallback (at or above cap) ---------------------------

func TestOktaProvider_FetchGroups_AtCap_TriggersAPI(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/api/v1/users/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, oktaGroupJSON("g1", "g2", "g3", "g4", "g5"))
	}))
	defer ts.Close()

	p := &OktaProvider{}
	p.ctx = context.Background()
	jc := buildJWTConfig(ts.URL, map[string]interface{}{
		"groups_cap":   3,
		"fetch_groups": true,
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	b.providerCtx = context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client())
	b.cachedConfig = &jwtConfig{OIDCDiscoveryCAPEM: ""}
	role := newOktaRole("groups", "sub")
	// exactly 3 groups == cap → fallback
	claims := map[string]interface{}{
		"sub":    "user@example.com",
		"groups": []interface{}{"x", "y", "z"},
	}

	result, err := p.FetchGroups(context.Background(), b, claims, role, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	groups := result.([]interface{})
	if len(groups) != 5 {
		t.Errorf("expected 5 groups from API, got %d", len(groups))
	}
}

func TestOktaProvider_FetchGroups_ClaimAbsent_TriggersAPI(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, oktaGroupJSON("vault-admin"))
	}))
	defer ts.Close()

	p := &OktaProvider{}
	p.ctx = context.Background()
	jc := buildJWTConfig(ts.URL, map[string]interface{}{
		"fetch_groups": true,
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	b.providerCtx = context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client())
	b.cachedConfig = &jwtConfig{OIDCDiscoveryCAPEM: ""}
	role := newOktaRole("groups", "sub")
	// no groups claim at all → fallback
	claims := map[string]interface{}{
		"sub": "user@example.com",
	}

	result, err := p.FetchGroups(context.Background(), b, claims, role, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	groups := result.([]interface{})
	if len(groups) != 1 || groups[0] != "vault-admin" {
		t.Errorf("unexpected groups from API: %v", groups)
	}
}

func TestOktaProvider_FetchGroups_AboveCap_TriggersAPI(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, oktaGroupJSON("full-g1", "full-g2"))
	}))
	defer ts.Close()

	p := &OktaProvider{}
	p.ctx = context.Background()
	jc := buildJWTConfig(ts.URL, map[string]interface{}{
		"groups_cap":   2,
		"fetch_groups": true,
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	b.providerCtx = context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client())
	b.cachedConfig = &jwtConfig{OIDCDiscoveryCAPEM: ""}
	role := newOktaRole("groups", "sub")
	// 3 groups > cap of 2 → fallback
	claims := map[string]interface{}{
		"sub":    "user@example.com",
		"groups": []interface{}{"a", "b", "c"},
	}

	result, err := p.FetchGroups(context.Background(), b, claims, role, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	groups := result.([]interface{})
	if len(groups) != 2 {
		t.Errorf("expected 2 groups from API, got %d", len(groups))
	}
}

func TestOktaProvider_FetchGroups_APIFallback_WithFilter(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, oktaGroupJSON("vault-admin", "corp-all", "vault-readonly", "ad-sync-group"))
	}))
	defer ts.Close()

	p := &OktaProvider{}
	p.ctx = context.Background()
	jc := buildJWTConfig(ts.URL, map[string]interface{}{
		"groups_filter": "^vault-",
		"fetch_groups":  true,
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	b.providerCtx = context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client())
	b.cachedConfig = &jwtConfig{OIDCDiscoveryCAPEM: ""}
	role := newOktaRole("groups", "sub")
	// no groups claim → API fallback
	claims := map[string]interface{}{
		"sub": "user@example.com",
	}

	result, err := p.FetchGroups(context.Background(), b, claims, role, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	groups := result.([]interface{})
	if len(groups) != 2 {
		t.Errorf("expected 2 filtered groups, got %d: %v", len(groups), groups)
	}
	for _, g := range groups {
		if !strings.HasPrefix(g.(string), "vault-") {
			t.Errorf("expected only vault- groups, got %q", g)
		}
	}
}

func TestOktaProvider_FetchGroups_EmptyAPIResult_NoError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	}))
	defer ts.Close()

	p := &OktaProvider{}
	p.ctx = context.Background()
	jc := buildJWTConfig(ts.URL, map[string]interface{}{
		"fetch_groups": true,
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	b.providerCtx = context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client())
	b.cachedConfig = &jwtConfig{OIDCDiscoveryCAPEM: ""}
	role := newOktaRole("groups", "sub")
	claims := map[string]interface{}{
		"sub": "user@example.com",
	}

	result, err := p.FetchGroups(context.Background(), b, claims, role, nil)
	if err != nil {
		t.Fatalf("unexpected error for empty group list: %v", err)
	}
	groups, ok := result.([]interface{})
	if !ok {
		// nil result is also acceptable for empty list
		return
	}
	if len(groups) != 0 {
		t.Errorf("expected empty groups list, got %v", groups)
	}
}

// ---- resolveUserID tests ----------------------------------------------------

func TestOktaProvider_ResolveUserID_FromUserIDClaim(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"user_id_claim": "email",
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	role := newOktaRole("groups", "sub")
	claims := map[string]interface{}{
		"sub":   "00u1abc",
		"email": "user@example.com",
	}

	id, err := p.resolveUserID(b, claims, role)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "user@example.com" {
		t.Errorf("expected user@example.com, got %q", id)
	}
}

func TestOktaProvider_ResolveUserID_FallsBackToRoleUserClaim(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", nil) // no user_id_claim
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	role := newOktaRole("groups", "sub") // role.UserClaim = "sub"
	claims := map[string]interface{}{
		"sub": "00u1abc",
	}

	id, err := p.resolveUserID(b, claims, role)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "00u1abc" {
		t.Errorf("expected 00u1abc, got %q", id)
	}
}

func TestOktaProvider_ResolveUserID_ClaimNotInToken_Error(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"user_id_claim": "email",
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	role := newOktaRole("groups", "sub")
	claims := map[string]interface{}{
		"sub": "00u1abc",
		// email claim absent
	}

	_, err := p.resolveUserID(b, claims, role)
	if err == nil {
		t.Fatal("expected error when user_id_claim not found in token")
	}
	if !strings.Contains(err.Error(), "email") {
		t.Errorf("expected error to mention claim name, got: %v", err)
	}
}

func TestOktaProvider_ResolveUserID_ClaimNotString_Error(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"user_id_claim": "sub",
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	role := newOktaRole("groups", "sub")
	claims := map[string]interface{}{
		"sub": 12345, // not a string
	}

	_, err := p.resolveUserID(b, claims, role)
	if err == nil {
		t.Fatal("expected error when claim value is not a string")
	}
}

func TestOktaProvider_ResolveUserID_BothClaimsUnset_Error(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", nil) // no user_id_claim
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	role := newOktaRole("groups", "") // role.UserClaim also empty
	claims := map[string]interface{}{
		"sub": "00u1abc",
	}

	_, err := p.resolveUserID(b, claims, role)
	if err == nil {
		t.Fatal("expected error when both user_id_claim and role.UserClaim are empty")
	}
}

// ---- getOktaGroups pagination tests -----------------------------------------

func TestOktaProvider_GetOktaGroups_SinglePage(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// no Link header → single page
		fmt.Fprint(w, oktaGroupJSON("g1", "g2", "g3"))
	}))
	defer ts.Close()

	p := &OktaProvider{
		ctx: context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client()),
		config: OktaProviderConfig{
			OrgURL:      ts.URL,
			APIToken:    "test-token",
			FetchGroups: true,
			GroupsCap:   defaultOktaGroupsCap,
		},
	}

	groups, err := p.getOktaGroups("user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != 3 {
		t.Errorf("expected 3 groups, got %d", len(groups))
	}
}

func TestOktaProvider_GetOktaGroups_MultiPage_PaginationFollowed(t *testing.T) {
	page := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		page++
		switch page {
		case 1:
			// First page — include Link: rel="next"
			w.Header().Set("Link", fmt.Sprintf(`<https://%s/api/v1/users/user%%40example.com/groups?after=cursor1&limit=200>; rel="next"`, r.Host))
			fmt.Fprint(w, oktaGroupJSON("g1", "g2", "g3"))
		case 2:
			// Second page — no next link
			fmt.Fprint(w, oktaGroupJSON("g4", "g5"))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	p := &OktaProvider{
		ctx: context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client()),
		config: OktaProviderConfig{
			OrgURL:      ts.URL,
			APIToken:    "test-token",
			FetchGroups: true,
			GroupsCap:   defaultOktaGroupsCap,
		},
	}

	groups, err := p.getOktaGroups("user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != 5 {
		t.Errorf("expected 5 groups across 2 pages, got %d: %v", len(groups), groups)
	}
	if page != 2 {
		t.Errorf("expected exactly 2 API calls, made %d", page)
	}
}

func TestOktaProvider_GetOktaGroups_API401_Error(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errorCode":"E0000011","errorSummary":"Invalid token"}`)
	}))
	defer ts.Close()

	p := &OktaProvider{
		ctx: context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client()),
		config: OktaProviderConfig{
			OrgURL:      ts.URL,
			APIToken:    "bad-token",
			FetchGroups: true,
			GroupsCap:   defaultOktaGroupsCap,
		},
	}

	_, err := p.getOktaGroups("user@example.com")
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected error to mention 401, got: %v", err)
	}
}

func TestOktaProvider_GetOktaGroups_API403_Error(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"errorCode":"E0000006","errorSummary":"You do not have permission"}`)
	}))
	defer ts.Close()

	p := &OktaProvider{
		ctx: context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client()),
		config: OktaProviderConfig{
			OrgURL:      ts.URL,
			APIToken:    "limited-token",
			FetchGroups: true,
			GroupsCap:   defaultOktaGroupsCap,
		},
	}

	_, err := p.getOktaGroups("user@example.com")
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("expected error to mention 403, got: %v", err)
	}
}

func TestOktaProvider_GetOktaGroups_API500_Error(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	p := &OktaProvider{
		ctx: context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client()),
		config: OktaProviderConfig{
			OrgURL:      ts.URL,
			APIToken:    "test-token",
			FetchGroups: true,
			GroupsCap:   defaultOktaGroupsCap,
		},
	}

	_, err := p.getOktaGroups("user@example.com")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestOktaProvider_GetOktaGroups_InvalidJSON_Error(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `not-valid-json`)
	}))
	defer ts.Close()

	p := &OktaProvider{
		ctx: context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client()),
		config: OktaProviderConfig{
			OrgURL:      ts.URL,
			APIToken:    "test-token",
			FetchGroups: true,
			GroupsCap:   defaultOktaGroupsCap,
		},
	}

	_, err := p.getOktaGroups("user@example.com")
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestOktaProvider_GetOktaGroups_EmptyProfileName_Dropped(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// one group has empty name — should be silently dropped
		fmt.Fprint(w, `[
			{"id":"id1","profile":{"name":"vault-admin"}},
			{"id":"id2","profile":{"name":""}},
			{"id":"id3","profile":{"name":"vault-readonly"}}
		]`)
	}))
	defer ts.Close()

	p := &OktaProvider{
		ctx: context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client()),
		config: OktaProviderConfig{
			OrgURL:      ts.URL,
			APIToken:    "test-token",
			FetchGroups: true,
			GroupsCap:   defaultOktaGroupsCap,
		},
	}

	groups, err := p.getOktaGroups("user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != 2 {
		t.Errorf("expected 2 groups (empty name dropped), got %d: %v", len(groups), groups)
	}
}

func TestOktaProvider_GetOktaGroups_SSWSAuthHeader(t *testing.T) {
	var gotAuth string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	}))
	defer ts.Close()

	p := &OktaProvider{
		ctx: context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client()),
		config: OktaProviderConfig{
			OrgURL:      ts.URL,
			APIToken:    "my-ssws-token",
			FetchGroups: true,
			GroupsCap:   defaultOktaGroupsCap,
		},
	}

	_, _ = p.getOktaGroups("user@example.com")
	expected := "SSWS my-ssws-token"
	if gotAuth != expected {
		t.Errorf("expected Authorization header %q, got %q", expected, gotAuth)
	}
}

func TestOktaProvider_GetOktaGroups_UserIDPathEncoded(t *testing.T) {
	var gotRequestURI string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RequestURI is the unmodified request-target as sent by the client,
		// preserving any percent-encoding applied by url.PathEscape.
		gotRequestURI = r.RequestURI
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	}))
	defer ts.Close()

	p := &OktaProvider{
		ctx: context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client()),
		config: OktaProviderConfig{
			OrgURL:      ts.URL,
			APIToken:    "test-token",
			FetchGroups: true,
			GroupsCap:   defaultOktaGroupsCap,
		},
	}

	// Use a user ID containing a space — url.PathEscape encodes it as %20.
	_, _ = p.getOktaGroups("john doe")
	if !strings.Contains(gotRequestURI, "john%20doe") {
		t.Errorf("expected space percent-encoded as %%20 in request URI, got %q", gotRequestURI)
	}
}

// ---- nextLink helper tests --------------------------------------------------

func TestNextLink_Present(t *testing.T) {
	headers := []string{
		`<https://example.okta.com/api/v1/users/me/groups?after=cursor>; rel="next"`,
	}
	got := nextLink(headers)
	want := "https://example.okta.com/api/v1/users/me/groups?after=cursor"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestNextLink_Absent(t *testing.T) {
	headers := []string{
		`<https://example.okta.com/api/v1/users/me/groups?limit=200>; rel="self"`,
	}
	got := nextLink(headers)
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestNextLink_MultipleHeaders_ReturnsNext(t *testing.T) {
	headers := []string{
		`<https://example.okta.com/api/v1/users/me/groups?limit=200>; rel="self"`,
		`<https://example.okta.com/api/v1/users/me/groups?after=cur&limit=200>; rel="next"`,
	}
	got := nextLink(headers)
	want := "https://example.okta.com/api/v1/users/me/groups?after=cur&limit=200"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestNextLink_Empty(t *testing.T) {
	got := nextLink([]string{})
	if got != "" {
		t.Errorf("expected empty string for empty headers, got %q", got)
	}
}

func TestNextLink_MalformedHeader(t *testing.T) {
	headers := []string{"not-a-link-header"}
	got := nextLink(headers)
	if got != "" {
		t.Errorf("expected empty string for malformed header, got %q", got)
	}
}

// ---- applyGroupsFilter tests ------------------------------------------------

func TestApplyGroupsFilter_MatchesSubset(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"groups_filter": "^vault-",
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	list := []interface{}{"vault-admin", "corp-all", "vault-readonly", "ad-sync"}
	result := p.applyGroupsFilter(b, list)
	if len(result) != 2 {
		t.Errorf("expected 2 matching groups, got %d: %v", len(result), result)
	}
}

func TestApplyGroupsFilter_MatchesAll(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"groups_filter": ".*",
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	list := []interface{}{"g1", "g2", "g3"}
	result := p.applyGroupsFilter(b, list)
	if len(result) != 3 {
		t.Errorf("expected all 3 groups, got %d", len(result))
	}
}

func TestApplyGroupsFilter_MatchesNone(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"groups_filter": "^nomatch-",
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	list := []interface{}{"g1", "g2", "g3"}
	result := p.applyGroupsFilter(b, list)
	if len(result) != 0 {
		t.Errorf("expected 0 matching groups, got %d", len(result))
	}
}

func TestApplyGroupsFilter_NonStringEntriesDropped(t *testing.T) {
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", map[string]interface{}{
		"groups_filter": ".*",
	})
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	b := newOktaTestBackend(t)
	list := []interface{}{"valid-group", 123, nil, "another-group"}
	result := p.applyGroupsFilter(b, list)
	if len(result) != 2 {
		t.Errorf("expected 2 string groups (non-strings dropped), got %d: %v", len(result), result)
	}
}

// ---- backward compatibility test --------------------------------------------

func TestOktaProvider_BackwardCompat_NoProviderConfig_GeneralFlowUnaffected(t *testing.T) {
	// Verifies that OktaProvider is entirely opt-in: when provider_config is
	// absent, ProviderMap returns nil and the general JWT flow runs unchanged.
	pm := ProviderMap()
	if pm["okta"] == nil {
		t.Fatal("okta must be registered in ProviderMap")
	}
	// Absence of provider_config means NewProviderConfig returns (nil, nil)
	// — tested at the framework level; here we just confirm registration.
	p, ok := pm["okta"].(*OktaProvider)
	if !ok {
		t.Fatalf("expected *OktaProvider in ProviderMap, got %T", pm["okta"])
	}
	_ = p
}

func TestOktaProvider_BackwardCompat_FetchGroupsDefaultFalse(t *testing.T) {
	// When fetch_groups key is absent from provider_config, it defaults to false.
	// Existing configs without fetch_groups therefore use only token groups.
	// fetch_groups must be explicitly set to true to enable API fetching.
	p := &OktaProvider{}
	jc := buildJWTConfig("https://example.okta.com", nil)
	// Confirm key is absent
	delete(jc.ProviderConfig, "fetch_groups")
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if p.config.FetchGroups {
		t.Error("expected FetchGroups=false when key absent")
	}
}

func TestOktaProvider_BackwardCompat_FutureField_FetchGroupsDisabled_NoFailure(t *testing.T) {
	// Simulates a future scenario: provider_config has provider=okta and some
	// new unrelated field, but fetch_groups=false. A user with exactly 100
	// groups (default cap) must not trigger the API fallback and must not fail
	// due to missing org_url/api_token.
	p := &OktaProvider{}
	jc := &jwtConfig{
		OIDCDiscoveryURL: "https://example.okta.com",
		ProviderConfig: map[string]interface{}{
			"provider":       "okta",
			"fetch_groups":   false,
			"future_field_x": "some-value", // hypothetical future field
			// no api_token, no org_url
		},
	}
	if err := p.Initialize(context.Background(), jc); err != nil {
		t.Fatalf("initialize should succeed with fetch_groups=false even without api_token: %v", err)
	}

	b := newOktaTestBackend(t)
	role := newOktaRole("groups", "sub")

	// user has exactly 100 groups — the default cap
	groups100 := make([]interface{}, 100)
	for i := range groups100 {
		groups100[i] = fmt.Sprintf("group-%d", i)
	}
	claims := map[string]interface{}{
		"sub":    "user@example.com",
		"groups": groups100,
	}

	// Must NOT fail — fetch_groups=false means use token as-is
	result, err := p.FetchGroups(context.Background(), b, claims, role, nil)
	if err != nil {
		t.Fatalf("unexpected error with fetch_groups=false and 100 groups: %v", err)
	}
	resultGroups, ok := result.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", result)
	}
	if len(resultGroups) != 100 {
		t.Errorf("expected 100 groups from token, got %d", len(resultGroups))
	}
}
