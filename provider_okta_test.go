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
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// oktaServer is a minimal mock that serves OIDC discovery plus the
// /api/v1/users/me/groups endpoint with RFC 5988 Link-header
// pagination. It intentionally does not use the Okta SDK so the test
// pins the exact wire format the provider relies on.
type oktaServer struct {
	t       *testing.T
	server  *httptest.Server
	pages   [][]oktaGroup
	calls   int32
	status  int
	authOK  func(string) bool
	reqAuth string
}

func newOktaServer(t *testing.T, pages [][]oktaGroup) *oktaServer {
	s := &oktaServer{t: t, pages: pages, status: http.StatusOK}
	s.server = httptest.NewTLSServer(s)
	return s
}

func (s *oktaServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if strings.HasPrefix(r.URL.Path, "/api/v1/users/me/groups") {
		s.reqAuth = r.Header.Get("Authorization")
		if s.authOK != nil && !s.authOK(s.reqAuth) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errorCode":"E0000005"}`))
			return
		}

		n := int(atomic.AddInt32(&s.calls, 1)) - 1
		if n >= len(s.pages) {
			s.t.Fatalf("unexpected extra page request (call #%d, only %d pages configured)", n+1, len(s.pages))
		}

		// If more pages remain, advertise a rel="next" link whose
		// `page=` query is what the provider will resend to us.
		if n < len(s.pages)-1 {
			nextURL := fmt.Sprintf("%s/api/v1/users/me/groups?after=page%d", s.server.URL, n+1)
			w.Header().Add("Link", fmt.Sprintf(`<%s>; rel="next"`, nextURL))
		}
		w.Header().Add("Link", fmt.Sprintf(`<%s/api/v1/users/me/groups>; rel="self"`, s.server.URL))

		if s.status != http.StatusOK {
			w.WriteHeader(s.status)
		}
		_ = json.NewEncoder(w).Encode(s.pages[n])
		return
	}

	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		fmt.Fprintf(w, `{
			"issuer": "%s",
			"authorization_endpoint": "%s/oauth2/v1/authorize",
			"token_endpoint": "%s/oauth2/v1/token",
			"jwks_uri": "%s/oauth2/v1/keys",
			"userinfo_endpoint": "%s/oauth2/v1/userinfo"
		}`, s.server.URL, s.server.URL, s.server.URL, s.server.URL, s.server.URL)
	default:
		s.t.Fatalf("unexpected path: %q", r.URL.Path)
	}
}

func (s *oktaServer) tlsCertPEM() (string, error) {
	cert := s.server.Certificate()
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// oktaGroupsWithNames is a small helper that builds n oktaGroup
// records with deterministic names like "grp-0001", useful for
// truncation/pagination tests.
func oktaGroupsWithNames(prefix string, n int) []oktaGroup {
	out := make([]oktaGroup, n)
	for i := 0; i < n; i++ {
		out[i] = oktaGroup{
			ID: fmt.Sprintf("id-%s-%04d", prefix, i),
			Profile: oktaGroupProfile{
				Name: fmt.Sprintf("%s-%04d", prefix, i),
			},
		}
	}
	return out
}

// configureOktaBackend writes an oidc config with provider_config set
// to the okta provider, and creates a role that requests the groups
// claim. Returns the initialized provider and a ready-to-use role.
func configureOktaBackend(t *testing.T, s *oktaServer) (*jwtAuthBackend, logical.Storage, CustomProvider, *jwtRole) {
	t.Helper()
	b, storage := getBackend(t)

	cert, err := s.tlsCertPEM()
	require.NoError(t, err)

	configData := map[string]interface{}{
		"oidc_discovery_url":    s.server.URL,
		"oidc_discovery_ca_pem": cert,
		"oidc_client_id":        "client-id",
		"oidc_client_secret":    "client-secret",
		"default_role":          "test",
		"bound_issuer":          "http://vault.example.com/",
		"provider_config": map[string]interface{}{
			"provider": "okta",
			"org_url":  s.server.URL,
			"groups_cap": 100,
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
	require.False(t, resp != nil && resp.IsError(), "config write returned error: %#v", resp)

	roleData := map[string]interface{}{
		"user_claim":            "sub",
		"groups_claim":          "groups",
		"allowed_redirect_uris": []string{"https://example.com"},
	}
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Storage:   storage,
		Data:      roleData,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "role write returned error: %#v", resp)

	ctx := context.Background()
	cfg, err := b.(*jwtAuthBackend).config(ctx, storage)
	require.NoError(t, err)

	provider, err := NewProviderConfig(ctx, cfg, ProviderMap())
	require.NoError(t, err)
	require.NotNil(t, provider)

	role := &jwtRole{GroupsClaim: "groups"}
	return b.(*jwtAuthBackend), storage, provider, role
}

func TestOktaProvider_FetchGroups_MissingClaim_FetchesFromAPI(t *testing.T) {
	s := newOktaServer(t, [][]oktaGroup{
		{{ID: "g1", Profile: oktaGroupProfile{Name: "eng"}}, {ID: "g2", Profile: oktaGroupProfile{Name: "sec"}}},
	})
	defer s.server.Close()

	b, _, provider, role := configureOktaBackend(t, s)

	allClaims := map[string]interface{}{"sub": "user@example.com"}
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "access.token.value"})

	got, err := b.fetchGroups(context.Background(), provider, allClaims, role, tokenSource)
	assert.NoError(t, err)
	assert.Equal(t, []interface{}{"eng", "sec"}, got)
	assert.Equal(t, "Bearer access.token.value", s.reqAuth)
	assert.Equal(t, int32(1), atomic.LoadInt32(&s.calls))
}

func TestOktaProvider_FetchGroups_TruncatedClaim_FetchesFromAPI(t *testing.T) {
	// Exactly-cap length triggers the API fallback.
	s := newOktaServer(t, [][]oktaGroup{
		oktaGroupsWithNames("full", 150),
	})
	defer s.server.Close()

	b, _, provider, role := configureOktaBackend(t, s)

	truncated := make([]interface{}, 100)
	for i := range truncated {
		truncated[i] = fmt.Sprintf("trunc-%04d", i)
	}
	allClaims := map[string]interface{}{
		"sub":    "user@example.com",
		"groups": truncated,
	}
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"})

	got, err := b.fetchGroups(context.Background(), provider, allClaims, role, tokenSource)
	assert.NoError(t, err)
	list, ok := got.([]interface{})
	require.True(t, ok, "expected []interface{}, got %T", got)
	assert.Len(t, list, 150)
	assert.Equal(t, "full-0000", list[0])
	assert.Equal(t, "full-0149", list[149])
	assert.Equal(t, int32(1), atomic.LoadInt32(&s.calls))
}

func TestOktaProvider_FetchGroups_UntrucatedClaim_PassesThrough(t *testing.T) {
	s := newOktaServer(t, [][]oktaGroup{
		// No pages configured; any API call is a test failure.
	})
	defer s.server.Close()

	b, _, provider, role := configureOktaBackend(t, s)

	allClaims := map[string]interface{}{
		"sub":    "user@example.com",
		"groups": []interface{}{"eng", "sec", "oncall"},
	}
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"})

	got, err := b.fetchGroups(context.Background(), provider, allClaims, role, tokenSource)
	assert.NoError(t, err)
	assert.Equal(t, []interface{}{"eng", "sec", "oncall"}, got)
	assert.Equal(t, int32(0), atomic.LoadInt32(&s.calls), "API must not be called when claim is short")
}

func TestOktaProvider_FetchGroups_Paginated(t *testing.T) {
	s := newOktaServer(t, [][]oktaGroup{
		oktaGroupsWithNames("p1", 50),
		oktaGroupsWithNames("p2", 50),
		oktaGroupsWithNames("p3", 37),
	})
	defer s.server.Close()

	b, _, provider, role := configureOktaBackend(t, s)

	allClaims := map[string]interface{}{"sub": "user@example.com"}
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"})

	got, err := b.fetchGroups(context.Background(), provider, allClaims, role, tokenSource)
	assert.NoError(t, err)
	list, ok := got.([]interface{})
	require.True(t, ok)
	assert.Len(t, list, 137)
	assert.Equal(t, "p1-0000", list[0])
	assert.Equal(t, "p2-0000", list[50])
	assert.Equal(t, "p3-0036", list[136])
	assert.Equal(t, int32(3), atomic.LoadInt32(&s.calls))
}

func TestOktaProvider_FetchGroups_APIError(t *testing.T) {
	s := newOktaServer(t, [][]oktaGroup{
		{{ID: "g1", Profile: oktaGroupProfile{Name: "eng"}}},
	})
	s.status = http.StatusForbidden
	defer s.server.Close()

	b, _, provider, role := configureOktaBackend(t, s)

	allClaims := map[string]interface{}{"sub": "user@example.com"}
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"})

	_, err := b.fetchGroups(context.Background(), provider, allClaims, role, tokenSource)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "okta api returned 403")
}

func TestOktaProvider_FetchGroups_EmptyAccessToken(t *testing.T) {
	s := newOktaServer(t, [][]oktaGroup{{}})
	defer s.server.Close()

	b, _, provider, role := configureOktaBackend(t, s)

	allClaims := map[string]interface{}{"sub": "user@example.com"}
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: ""})

	_, err := b.fetchGroups(context.Background(), provider, allClaims, role, tokenSource)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access token is empty")
}

func TestOktaProvider_Initialize_Validation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     map[string]interface{}
		wantErr string
	}{
		{
			name:    "missing org_url",
			cfg:     map[string]interface{}{"provider": "okta"},
			wantErr: "'org_url' must be set",
		},
		{
			name:    "non-https org_url",
			cfg:     map[string]interface{}{"provider": "okta", "org_url": "http://example.okta.com"},
			wantErr: "must use https",
		},
		{
			name:    "negative groups_cap",
			cfg:     map[string]interface{}{"provider": "okta", "org_url": "https://example.okta.com", "groups_cap": -1},
			wantErr: "groups_cap must be >= 0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &OktaProvider{}
			err := p.Initialize(context.Background(), &jwtConfig{ProviderConfig: tc.cfg})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestOktaProvider_Initialize_DefaultsGroupsCap(t *testing.T) {
	p := &OktaProvider{}
	err := p.Initialize(context.Background(), &jwtConfig{ProviderConfig: map[string]interface{}{
		"provider": "okta",
		"org_url":  "https://example.okta.com",
	}})
	require.NoError(t, err)
	assert.Equal(t, defaultOktaGroupsCap, p.config.GroupsCap)
}

func TestNextLink(t *testing.T) {
	cases := []struct {
		name    string
		headers []string
		want    string
	}{
		{"none", []string{`<https://x/self>; rel="self"`}, ""},
		{"next present", []string{
			`<https://x/self>; rel="self"`,
			`<https://x/after=abc>; rel="next"`,
		}, "https://x/after=abc"},
		{"single header with next", []string{`<https://x/after=abc>; rel="next"`}, "https://x/after=abc"},
		{"empty", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, nextLink(tc.headers))
		})
	}
}
