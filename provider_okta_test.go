// Copyright IBM Corp. 2018, 2026
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// test server

// oktaServer is a TLS test server that simultaneously serves OIDC discovery
// (so Vault can write a valid config) and the Okta admin groups API
// (so FetchGroups calls are intercepted without reaching the internet).
type oktaServer struct {
	t      *testing.T
	server *httptest.Server

	// groups is the list of group names returned by the admin API.
	groups []string
	// apiCallCount is incremented on every /api/v1/users/*/groups hit.
	apiCallCount int
}

func newOktaServer(t *testing.T) *oktaServer {
	t.Helper()
	s := &oktaServer{t: t}
	s.server = httptest.NewTLSServer(s)
	t.Cleanup(s.server.Close)
	return s
}

func (s *oktaServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/.well-known/openid-configuration":
		w.Write([]byte(strings.Replace(`{
			"issuer":                  "%s",
			"authorization_endpoint": "%s/auth",
			"token_endpoint":         "%s/token",
			"jwks_uri":               "%s/certs",
			"userinfo_endpoint":      "%s/userinfo"
		}`, "%s", s.server.URL, -1)))
	case strings.Contains(r.URL.Path, "/api/v1/users/"):
		s.apiCallCount++
		json.NewEncoder(w).Encode(makeOktaGroups(s.groups...)) //nolint:errcheck
	default:
		s.t.Errorf("unexpected request path: %q", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// getTLSCert returns the server's self-signed certificate in PEM format,
// suitable for use as oidc_discovery_ca_pem.
func (s *oktaServer) getTLSCert() (string, error) {
	cert := s.server.Certificate()
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// makeOktaGroups builds a slice of oktaGroup values for JSON encoding.
func makeOktaGroups(names ...string) []oktaGroup {
	out := make([]oktaGroup, len(names))
	for i, n := range names {
		out[i] = oktaGroup{ID: fmt.Sprintf("id-%d", i), Profile: oktaGroupProfile{Name: n}}
	}
	return out
}

// oktaGroupJSON returns a JSON-encoded Okta groups array used by
// getOktaGroups unit tests that construct their own httptest servers.
func oktaGroupJSON(names ...string) string {
	b, _ := json.Marshal(makeOktaGroups(names...))
	return string(b)
}

// backend helpers

// newOktaBackend configures a full Vault jwtAuthBackend via HandleRequest,
// pointing both OIDC discovery and the Okta admin API at ts.
// providerExtra merges into the provider_config map on top of the defaults
// (provider=okta, org_url=ts.URL, api_token=test-token).
// A role named "test" with user_claim=sub and groups_claim=groups is created.
func newOktaBackend(t *testing.T, ts *oktaServer, providerExtra map[string]interface{}) (logical.Backend, logical.Storage) {
	t.Helper()
	cert, err := ts.getTLSCert()
	require.NoError(t, err)

	pc := map[string]interface{}{
		"provider":  "okta",
		"org_url":   ts.server.URL,
		"api_token": "test-token",
	}
	for k, v := range providerExtra {
		pc[k] = v
	}

	b, storage := getBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"oidc_discovery_url":    ts.server.URL,
			"oidc_discovery_ca_pem": cert,
			"oidc_client_id":        "abc",
			"oidc_client_secret":    "def",
			"bound_issuer":          ts.server.URL,
			"provider_config":       pc,
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Falsef(t, resp != nil && resp.IsError(), "unexpected config error: %v", resp)

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Storage:   storage,
		Data: map[string]interface{}{
			"user_claim":            "sub",
			"groups_claim":          "groups",
			"allowed_redirect_uris": []string{"https://example.com"},
		},
	}
	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Falsef(t, resp != nil && resp.IsError(), "unexpected role error: %v", resp)

	return b, storage
}

// injectTLSClient replaces the backend's providerCtx with one that carries the
// test server's HTTP client. In FetchGroups, b.providerCtx is passed to
// b.createCAContext which extracts the HTTP client value; that client is then
// passed directly into getOktaGroups. cachedConfig.OIDCDiscoveryCAPEM is
// cleared to prevent createCAContext from building a conflicting CA-pinned
// transport that would shadow the injected client.
func injectTLSClient(b logical.Backend, ts *oktaServer) {
	backend := b.(*jwtAuthBackend)
	if backend.cachedConfig != nil {
		backend.cachedConfig.OIDCDiscoveryCAPEM = ""
	}
	backend.providerCtx = context.WithValue(
		context.Background(), oauth2.HTTPClient, ts.server.Client(),
	)
}

// ---- Initialize tests -------------------------------------------------------

func TestOktaProvider_Initialize(t *testing.T) {
	tests := []struct {
		name         string
		providerCfg  map[string]interface{}
		discoveryURL string
		wantErr      bool
		errContains  string
		check        func(t *testing.T, p *OktaProvider)
	}{
		{
			name: "valid config sets fields and defaults",
			providerCfg: map[string]interface{}{
				"org_url":   "https://example.okta.com",
				"api_token": "test-token",
			},
			check: func(t *testing.T, p *OktaProvider) {
				assert.Equal(t, "https://example.okta.com", p.config.OrgURL)
				assert.Equal(t, defaultOktaGroupsCap, p.config.GroupsCap)
				assert.False(t, p.config.FetchGroups, "fetch_groups absent should default to false")
			},
		},
		{
			name:         "org_url derived from discovery URL when absent",
			providerCfg:  map[string]interface{}{},
			discoveryURL: "https://example.okta.com",
			check: func(t *testing.T, p *OktaProvider) {
				assert.Equal(t, "https://example.okta.com", p.config.OrgURL)
			},
		},
		{
			name:         "org_url derived strips path from custom auth server URL",
			providerCfg:  map[string]interface{}{},
			discoveryURL: "https://example.okta.com/oauth2/aus1abc123",
			check: func(t *testing.T, p *OktaProvider) {
				assert.Equal(t, "https://example.okta.com", p.config.OrgURL)
			},
		},
		{
			name: "fetch_groups absent defaults to false",
			providerCfg: map[string]interface{}{
				"org_url":   "https://example.okta.com",
				"api_token": "test-token",
			},
			check: func(t *testing.T, p *OktaProvider) {
				assert.False(t, p.config.FetchGroups)
			},
		},
		{
			name: "fetch_groups=true stored correctly",
			providerCfg: map[string]interface{}{
				"org_url":      "https://example.okta.com",
				"api_token":    "test-token",
				"fetch_groups": true,
			},
			check: func(t *testing.T, p *OktaProvider) {
				assert.True(t, p.config.FetchGroups)
			},
		},
		{
			name: "fetch_groups=false does not require api_token",
			providerCfg: map[string]interface{}{
				"org_url":      "https://example.okta.com",
				"fetch_groups": false,
			},
		},
		{
			name: "missing api_token with fetch_groups=true is an error",
			providerCfg: map[string]interface{}{
				"org_url":      "https://example.okta.com",
				"fetch_groups": true,
			},
			wantErr:     true,
			errContains: "api_token",
		},
		{
			name: "non-https org_url is an error",
			providerCfg: map[string]interface{}{
				"org_url":   "http://example.okta.com",
				"api_token": "test-token",
			},
			wantErr:     true,
			errContains: "https",
		},
		{
			name: "negative groups_cap is an error",
			providerCfg: map[string]interface{}{
				"org_url":    "https://example.okta.com",
				"api_token":  "test-token",
				"groups_cap": -1,
			},
			wantErr: true,
		},
		{
			name: "groups_cap=0 defaults to 100",
			providerCfg: map[string]interface{}{
				"org_url":    "https://example.okta.com",
				"api_token":  "test-token",
				"groups_cap": 0,
			},
			check: func(t *testing.T, p *OktaProvider) {
				assert.Equal(t, defaultOktaGroupsCap, p.config.GroupsCap)
			},
		},
		{
			name: "invalid groups_filter regex is an error",
			providerCfg: map[string]interface{}{
				"org_url":       "https://example.okta.com",
				"api_token":     "test-token",
				"groups_filter": "[invalid",
			},
			wantErr:     true,
			errContains: "groups_filter",
		},
		{
			name: "valid groups_filter compiles regex",
			providerCfg: map[string]interface{}{
				"org_url":       "https://example.okta.com",
				"api_token":     "test-token",
				"groups_filter": "^vault-",
			},
			check: func(t *testing.T, p *OktaProvider) {
				assert.NotNil(t, p.groupsFilter)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OktaProvider{}
			discoveryURL := tt.discoveryURL
			if discoveryURL == "" {
				discoveryURL = "https://example.okta.com"
			}
			jc := &jwtConfig{
				OIDCDiscoveryURL: discoveryURL,
				ProviderConfig:   tt.providerCfg,
			}
			err := p.Initialize(context.Background(), jc)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, p)
			}
		})
	}
}

// SensitiveKeys

func TestOktaProvider_SensitiveKeys(t *testing.T) {
	p := &OktaProvider{}
	assert.Equal(t, []string{"api_token"}, p.SensitiveKeys())
}

// FetchGroups — fetch_groups=false (token-only path)

func TestOktaProvider_FetchGroups_FetchGroupsDisabled(t *testing.T) {
	ts := newOktaServer(t)
	ts.groups = []string{"api-group"} // must NOT appear in any result

	t.Run("uses token groups directly without calling API", func(t *testing.T) {
		b, storage := newOktaBackend(t, ts, map[string]interface{}{"fetch_groups": false})
		injectTLSClient(b, ts)
		ctx := context.Background()

		config, err := b.(*jwtAuthBackend).config(ctx, storage)
		require.NoError(t, err)
		provider, err := NewProviderConfig(ctx, config, ProviderMap())
		require.NoError(t, err)

		role := &jwtRole{GroupsClaim: "groups", UserClaim: "sub"}
		allClaims := map[string]interface{}{
			"sub":    "user@example.com",
			"groups": []interface{}{"token-g1", "token-g2"},
		}

		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "access-token"})
		ts.apiCallCount = 0
		result, err := b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, role, tokenSource)

		require.NoError(t, err)
		assert.Equal(t, []interface{}{"token-g1", "token-g2"}, result)
		assert.Equal(t, 0, ts.apiCallCount, "Okta API must not be called when fetch_groups=false")
	})

	t.Run("groups_filter applied to token groups", func(t *testing.T) {
		b, storage := newOktaBackend(t, ts, map[string]interface{}{
			"fetch_groups":  false,
			"groups_filter": "^vault-",
		})
		injectTLSClient(b, ts)
		ctx := context.Background()

		config, err := b.(*jwtAuthBackend).config(ctx, storage)
		require.NoError(t, err)
		provider, err := NewProviderConfig(ctx, config, ProviderMap())
		require.NoError(t, err)

		role := &jwtRole{GroupsClaim: "groups", UserClaim: "sub"}
		allClaims := map[string]interface{}{
			"sub":    "user@example.com",
			"groups": []interface{}{"vault-admin", "corp-everyone", "vault-readonly"},
		}

		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "access-token"})
		result, err := b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, role, tokenSource)

		require.NoError(t, err)
		groups, ok := normalizeList(result)
		require.True(t, ok)
		assert.Len(t, groups, 2)
		for _, g := range groups {
			assert.True(t, strings.HasPrefix(g.(string), "vault-"))
		}
	})
}

// FetchGroups — fast path (below cap, no API call)

func TestOktaProvider_FetchGroups_FastPath(t *testing.T) {
	ts := newOktaServer(t)
	ts.groups = []string{"api-group"} // must NOT appear in any result

	t.Run("groups below cap uses token without API call", func(t *testing.T) {
		b, storage := newOktaBackend(t, ts, map[string]interface{}{
			"fetch_groups": true,
			"groups_cap":   5,
		})
		injectTLSClient(b, ts)
		ctx := context.Background()

		config, err := b.(*jwtAuthBackend).config(ctx, storage)
		require.NoError(t, err)
		provider, err := NewProviderConfig(ctx, config, ProviderMap())
		require.NoError(t, err)

		role := &jwtRole{GroupsClaim: "groups", UserClaim: "sub"}
		allClaims := map[string]interface{}{
			"sub":    "user@example.com",
			"groups": []interface{}{"g1", "g2", "g3"}, // 3 < cap of 5
		}

		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "access-token"})
		ts.apiCallCount = 0
		result, err := b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, role, tokenSource)

		require.NoError(t, err)
		assert.Equal(t, 0, ts.apiCallCount, "API must not be called below cap")
		groups, ok := normalizeList(result)
		require.True(t, ok)
		assert.Len(t, groups, 3)
	})

	t.Run("groups below cap with filter — no API call, filter applied", func(t *testing.T) {
		b, storage := newOktaBackend(t, ts, map[string]interface{}{
			"fetch_groups":  true,
			"groups_cap":    5,
			"groups_filter": "^vault-",
		})
		injectTLSClient(b, ts)
		ctx := context.Background()

		config, err := b.(*jwtAuthBackend).config(ctx, storage)
		require.NoError(t, err)
		provider, err := NewProviderConfig(ctx, config, ProviderMap())
		require.NoError(t, err)

		role := &jwtRole{GroupsClaim: "groups", UserClaim: "sub"}
		allClaims := map[string]interface{}{
			"sub":    "user@example.com",
			"groups": []interface{}{"vault-admin", "corp-all", "vault-readonly"},
		}

		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "access-token"})
		ts.apiCallCount = 0
		result, err := b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, role, tokenSource)

		require.NoError(t, err)
		assert.Equal(t, 0, ts.apiCallCount, "API must not be called below cap")
		groups, ok := normalizeList(result)
		require.True(t, ok)
		assert.Len(t, groups, 2)
	})
}

// FetchGroups — API fallback (at or above cap)

func TestOktaProvider_FetchGroups_APIFallback(t *testing.T) {
	t.Run("groups equal to cap triggers API call", func(t *testing.T) {
		ts := newOktaServer(t)
		ts.groups = []string{"api-g1", "api-g2", "api-g3", "api-g4", "api-g5"}

		b, storage := newOktaBackend(t, ts, map[string]interface{}{
			"fetch_groups": true,
			"groups_cap":   3,
		})
		injectTLSClient(b, ts)
		ctx := context.Background()

		config, err := b.(*jwtAuthBackend).config(ctx, storage)
		require.NoError(t, err)
		provider, err := NewProviderConfig(ctx, config, ProviderMap())
		require.NoError(t, err)

		role := &jwtRole{GroupsClaim: "groups", UserClaim: "sub"}
		allClaims := map[string]interface{}{
			"sub":    "user@example.com",
			"groups": []interface{}{"x", "y", "z"}, // exactly 3 == cap
		}

		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "access-token"})
		result, err := b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, role, tokenSource)

		require.NoError(t, err)
		assert.Equal(t, 1, ts.apiCallCount, "API must be called at cap")
		groups, ok := normalizeList(result)
		require.True(t, ok)
		assert.Len(t, groups, 5)
	})

	t.Run("groups above cap triggers API call", func(t *testing.T) {
		ts := newOktaServer(t)
		ts.groups = []string{"full-g1", "full-g2"}

		b, storage := newOktaBackend(t, ts, map[string]interface{}{
			"fetch_groups": true,
			"groups_cap":   2,
		})
		injectTLSClient(b, ts)
		ctx := context.Background()

		config, err := b.(*jwtAuthBackend).config(ctx, storage)
		require.NoError(t, err)
		provider, err := NewProviderConfig(ctx, config, ProviderMap())
		require.NoError(t, err)

		role := &jwtRole{GroupsClaim: "groups", UserClaim: "sub"}
		allClaims := map[string]interface{}{
			"sub":    "user@example.com",
			"groups": []interface{}{"a", "b", "c"}, // 3 > cap of 2
		}

		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "access-token"})
		result, err := b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, role, tokenSource)

		require.NoError(t, err)
		groups, ok := normalizeList(result)
		require.True(t, ok)
		assert.Len(t, groups, 2)
	})

	t.Run("absent groups claim triggers API call", func(t *testing.T) {
		ts := newOktaServer(t)
		ts.groups = []string{"vault-admin"}

		b, storage := newOktaBackend(t, ts, map[string]interface{}{"fetch_groups": true})
		injectTLSClient(b, ts)
		ctx := context.Background()

		config, err := b.(*jwtAuthBackend).config(ctx, storage)
		require.NoError(t, err)
		provider, err := NewProviderConfig(ctx, config, ProviderMap())
		require.NoError(t, err)

		role := &jwtRole{GroupsClaim: "groups", UserClaim: "sub"}
		allClaims := map[string]interface{}{"sub": "user@example.com"} // no groups

		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "access-token"})
		result, err := b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, role, tokenSource)

		require.NoError(t, err)
		groups, ok := normalizeList(result)
		require.True(t, ok)
		assert.Equal(t, []interface{}{"vault-admin"}, groups)
	})

	t.Run("groups_filter applied to API results", func(t *testing.T) {
		ts := newOktaServer(t)
		ts.groups = []string{"vault-admin", "corp-all", "vault-readonly", "ad-sync-group"}

		b, storage := newOktaBackend(t, ts, map[string]interface{}{
			"fetch_groups":  true,
			"groups_filter": "^vault-",
		})
		injectTLSClient(b, ts)
		ctx := context.Background()

		config, err := b.(*jwtAuthBackend).config(ctx, storage)
		require.NoError(t, err)
		provider, err := NewProviderConfig(ctx, config, ProviderMap())
		require.NoError(t, err)

		role := &jwtRole{GroupsClaim: "groups", UserClaim: "sub"}
		allClaims := map[string]interface{}{"sub": "user@example.com"} // no groups → API

		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "access-token"})
		result, err := b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, role, tokenSource)

		require.NoError(t, err)
		groups, ok := normalizeList(result)
		require.True(t, ok)
		assert.Len(t, groups, 2)
		for _, g := range groups {
			assert.True(t, strings.HasPrefix(g.(string), "vault-"))
		}
	})

}

// resolveUserID unit tests

func TestOktaProvider_ResolveUserID(t *testing.T) {
	tests := []struct {
		name        string
		cfgClaim    string // user_id_claim in provider config
		roleClaim   string // role.UserClaim
		claims      map[string]interface{}
		wantID      string
		wantErr     bool
		errContains string
	}{
		{
			name:      "uses configured user_id_claim",
			cfgClaim:  "email",
			roleClaim: "sub",
			claims:    map[string]interface{}{"sub": "00u1abc", "email": "user@example.com"},
			wantID:    "user@example.com",
		},
		{
			name:      "falls back to role user_claim when user_id_claim unset",
			cfgClaim:  "",
			roleClaim: "sub",
			claims:    map[string]interface{}{"sub": "00u1abc"},
			wantID:    "00u1abc",
		},
		{
			name:        "claim absent from token returns error",
			cfgClaim:    "email",
			roleClaim:   "sub",
			claims:      map[string]interface{}{"sub": "00u1abc"},
			wantErr:     true,
			errContains: "email",
		},
		{
			name:      "claim value not a string returns error",
			cfgClaim:  "sub",
			roleClaim: "sub",
			claims:    map[string]interface{}{"sub": 12345},
			wantErr:   true,
		},
		{
			name:      "both user_id_claim and role.UserClaim empty returns error",
			cfgClaim:  "",
			roleClaim: "",
			claims:    map[string]interface{}{"sub": "00u1abc"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OktaProvider{}
			pc := map[string]interface{}{
				"org_url":   "https://example.okta.com",
				"api_token": "test-token",
			}
			if tt.cfgClaim != "" {
				pc["user_id_claim"] = tt.cfgClaim
			}
			jc := &jwtConfig{OIDCDiscoveryURL: "https://example.okta.com", ProviderConfig: pc}
			require.NoError(t, p.Initialize(context.Background(), jc))

			b, _ := getBackend(t)
			role := &jwtRole{GroupsClaim: "groups", UserClaim: tt.roleClaim}

			id, err := p.resolveUserID(b.(*jwtAuthBackend), tt.claims, role)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, id)
		})
	}
}

// getOktaGroups unit tests

func TestOktaProvider_GetOktaGroups(t *testing.T) {
	t.Run("single page returns all groups", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, oktaGroupJSON("g1", "g2", "g3"))
		}))
		defer ts.Close()

		p := &OktaProvider{
			config: OktaProviderConfig{OrgURL: ts.URL, APIToken: "tok", FetchGroups: true, GroupsCap: defaultOktaGroupsCap},
		}
		groups, err := p.getOktaGroups(context.Background(), ts.Client(), "user@example.com")

		require.NoError(t, err)
		assert.Len(t, groups, 3)
	})

	t.Run("pagination follows Link rel=next across pages", func(t *testing.T) {
		page := 0
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			page++
			switch page {
			case 1:
				w.Header().Set("Link", fmt.Sprintf(
					`<https://%s/api/v1/users/user%%40example.com/groups?after=cur&limit=200>; rel="next"`, r.Host))
				fmt.Fprint(w, oktaGroupJSON("g1", "g2", "g3"))
			case 2:
				fmt.Fprint(w, oktaGroupJSON("g4", "g5"))
			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
		}))
		defer ts.Close()

		p := &OktaProvider{
			config: OktaProviderConfig{OrgURL: ts.URL, APIToken: "tok", FetchGroups: true, GroupsCap: defaultOktaGroupsCap},
		}
		groups, err := p.getOktaGroups(context.Background(), ts.Client(), "user@example.com")

		require.NoError(t, err)
		assert.Len(t, groups, 5)
		assert.Equal(t, 2, page, "expected exactly 2 API pages")
	})

	t.Run("empty profile name is silently dropped", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[
				{"id":"id1","profile":{"name":"vault-admin"}},
				{"id":"id2","profile":{"name":""}},
				{"id":"id3","profile":{"name":"vault-readonly"}}
			]`)
		}))
		defer ts.Close()

		p := &OktaProvider{
			config: OktaProviderConfig{OrgURL: ts.URL, APIToken: "tok", FetchGroups: true, GroupsCap: defaultOktaGroupsCap},
		}
		groups, err := p.getOktaGroups(context.Background(), ts.Client(), "user@example.com")

		require.NoError(t, err)
		assert.Len(t, groups, 2, "group with empty name must be dropped")
	})

	t.Run("SSWS token sent in Authorization header", func(t *testing.T) {
		var gotAuth string
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, "[]")
		}))
		defer ts.Close()

		p := &OktaProvider{
			config: OktaProviderConfig{OrgURL: ts.URL, APIToken: "my-ssws-token", FetchGroups: true, GroupsCap: defaultOktaGroupsCap},
		}
		_, _ = p.getOktaGroups(context.Background(), ts.Client(), "user@example.com")

		assert.Equal(t, "SSWS my-ssws-token", gotAuth)
	})

	for _, tc := range []struct {
		name   string
		status int
		body   string
		errMsg string
	}{
		{"HTTP 401 returns error mentioning status", http.StatusUnauthorized, `{"errorCode":"E0000011"}`, "401"},
		{"HTTP 403 returns error mentioning status", http.StatusForbidden, `{"errorCode":"E0000006"}`, "403"},
		{"HTTP 500 returns error", http.StatusInternalServerError, "", "500"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer ts.Close()

			p := &OktaProvider{
				config: OktaProviderConfig{OrgURL: ts.URL, APIToken: "tok", FetchGroups: true, GroupsCap: defaultOktaGroupsCap},
			}
			_, err := p.getOktaGroups(context.Background(), ts.Client(), "user@example.com")

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}

	t.Run("invalid JSON response returns error", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `not-valid-json`)
		}))
		defer ts.Close()

		p := &OktaProvider{
			config: OktaProviderConfig{OrgURL: ts.URL, APIToken: "tok", FetchGroups: true, GroupsCap: defaultOktaGroupsCap},
		}
		_, err := p.getOktaGroups(context.Background(), ts.Client(), "user@example.com")

		require.Error(t, err)
	})
}

// nextLink helper tests

func TestNextLink(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    string
	}{
		{
			name:    "rel=next present",
			headers: []string{`<https://example.okta.com/api/v1/users/me/groups?after=cursor>; rel="next"`},
			want:    "https://example.okta.com/api/v1/users/me/groups?after=cursor",
		},
		{
			name:    "rel=self only returns empty string",
			headers: []string{`<https://example.okta.com/api/v1/users/me/groups?limit=200>; rel="self"`},
			want:    "",
		},
		{
			name: "multiple Link headers returns rel=next",
			headers: []string{
				`<https://example.okta.com/api/v1/users/me/groups?limit=200>; rel="self"`,
				`<https://example.okta.com/api/v1/users/me/groups?after=cur&limit=200>; rel="next"`,
			},
			want: "https://example.okta.com/api/v1/users/me/groups?after=cur&limit=200",
		},
		{
			name:    "empty header slice returns empty string",
			headers: []string{},
			want:    "",
		},
		{
			name:    "malformed header returns empty string",
			headers: []string{"not-a-link-header"},
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, nextLink(tt.headers))
		})
	}
}

// applyGroupsFilter unit tests

func TestOktaProvider_ApplyGroupsFilter(t *testing.T) {
	tests := []struct {
		name    string
		filter  string
		input   []interface{}
		wantLen int
	}{
		{
			name:    "matches subset",
			filter:  "^vault-",
			input:   []interface{}{"vault-admin", "corp-all", "vault-readonly", "ad-sync"},
			wantLen: 2,
		},
		{
			name:    "matches all",
			filter:  ".*",
			input:   []interface{}{"g1", "g2", "g3"},
			wantLen: 3,
		},
		{
			name:    "matches none",
			filter:  "^nomatch-",
			input:   []interface{}{"g1", "g2", "g3"},
			wantLen: 0,
		},
		{
			name:    "non-string entries are silently dropped",
			filter:  ".*",
			input:   []interface{}{"valid-group", 123, nil, "another-group"},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OktaProvider{}
			jc := &jwtConfig{
				OIDCDiscoveryURL: "https://example.okta.com",
				ProviderConfig: map[string]interface{}{
					"org_url":       "https://example.okta.com",
					"api_token":     "test-token",
					"groups_filter": tt.filter,
				},
			}
			require.NoError(t, p.Initialize(context.Background(), jc))

			b, _ := getBackend(t)
			result := p.applyGroupsFilter(b.(*jwtAuthBackend), tt.input)

			assert.Len(t, result, tt.wantLen)
		})
	}
}

// backward compatibility tests

func TestOktaProvider_BackwardCompat(t *testing.T) {
	t.Run("okta is registered in ProviderMap", func(t *testing.T) {
		pm := ProviderMap()
		require.NotNil(t, pm["okta"])
		_, ok := pm["okta"].(*OktaProvider)
		assert.True(t, ok)
	})

	t.Run("fetch_groups absent defaults to false — only token groups used", func(t *testing.T) {
		p := &OktaProvider{}
		jc := &jwtConfig{
			OIDCDiscoveryURL: "https://example.okta.com",
			ProviderConfig: map[string]interface{}{
				"org_url":   "https://example.okta.com",
				"api_token": "test-token",
				// fetch_groups intentionally absent
			},
		}
		require.NoError(t, p.Initialize(context.Background(), jc))
		assert.False(t, p.config.FetchGroups)
	})

	t.Run("fetch_groups=false with 100 token groups uses token as-is without API call", func(t *testing.T) {
		ts := newOktaServer(t)
		ts.groups = []string{"should-not-appear"}

		b, storage := newOktaBackend(t, ts, map[string]interface{}{"fetch_groups": false})
		injectTLSClient(b, ts)
		ctx := context.Background()

		config, err := b.(*jwtAuthBackend).config(ctx, storage)
		require.NoError(t, err)
		provider, err := NewProviderConfig(ctx, config, ProviderMap())
		require.NoError(t, err)

		role := &jwtRole{GroupsClaim: "groups", UserClaim: "sub"}
		groups100 := make([]interface{}, 100)
		for i := range groups100 {
			groups100[i] = fmt.Sprintf("group-%d", i)
		}
		allClaims := map[string]interface{}{"sub": "user@example.com", "groups": groups100}

		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "access-token"})
		result, err := b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, role, tokenSource)

		require.NoError(t, err)
		assert.Equal(t, 0, ts.apiCallCount, "API must not be called when fetch_groups=false")
		list, ok := normalizeList(result)
		require.True(t, ok)
		assert.Len(t, list, 100)
	})
}
