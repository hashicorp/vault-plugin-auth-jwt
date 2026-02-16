// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// roundTripFunc adapts a function to the http.RoundTripper interface.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type azureServer struct {
	t      *testing.T
	server *httptest.Server
}

func newAzureServer(t *testing.T) *azureServer {
	a := new(azureServer)
	a.t = t
	a.server = httptest.NewTLSServer(a)

	return a
}

func (a *azureServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		w.Write([]byte(strings.Replace(`
			{
				"issuer": "%s",
				"authorization_endpoint": "%s/auth",
				"token_endpoint": "%s/oauth2/v2.0/token",
				"jwks_uri": "%s/certs",
				"userinfo_endpoint": "%s/userinfo"
			}`, "%s", a.server.URL, -1)))
	case "/getMemberObjects":
		groups := azureGroups{
			Value: []interface{}{"group1", "group2"},
		}
		gBytes, _ := json.Marshal(groups)
		w.Write(gBytes)
	default:
		a.t.Fatalf("unexpected path: %q", r.URL.Path)
	}
}

// getTLSCert returns the certificate for this provider in PEM format
func (a *azureServer) getTLSCert() (string, error) {
	cert := a.server.Certificate()
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

func TestLogin_fetchGroups(t *testing.T) {
	aServer := newAzureServer(t)
	aCert, err := aServer.getTLSCert()
	require.NoError(t, err)

	b, storage := getBackend(t)
	ctx := context.Background()

	data := map[string]interface{}{
		"oidc_discovery_url":    aServer.server.URL,
		"oidc_discovery_ca_pem": aCert,
		"oidc_client_id":        "abc",
		"oidc_client_secret":    "def",
		"default_role":          "test",
		"bound_issuer":          "http://vault.example.com/",
		"provider_config": map[string]interface{}{
			"provider": "azure",
		},
	}

	// basic configuration
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v\n", err, resp)
	}

	// set up test role
	data = map[string]interface{}{
		"user_claim":            "email",
		"groups_claim":          "groups",
		"allowed_redirect_uris": []string{"https://example.com"},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v\n", err, resp)
	}

	role := &jwtRole{
		GroupsClaim: "groups",
	}
	allClaims := map[string]interface{}{
		"_claim_names": H{
			"groups": "src1",
		},
		"_claim_sources": H{
			"src1": H{
				"endpoint": aServer.server.URL + "/getMemberObjects",
			},
		},
	}

	// Ensure b.cachedConfig is populated
	config, err := b.(*jwtAuthBackend).config(ctx, storage)
	if err != nil {
		t.Fatal(err)
	}

	// Initialize the azure provider
	provider, err := NewProviderConfig(ctx, config, ProviderMap())
	if err != nil {
		t.Fatal(err)
	}

	// Ensure groups are as expected
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test.access.token"})
	groupsResp, err := b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, role, tokenSource)
	assert.NoError(t, err)
	assert.Equal(t, []interface{}{"group1", "group2"}, groupsResp)
}

func TestAzureProvider_FetchGroups_WithFetchGroupsEnabled(t *testing.T) {
	expectedGroups := []interface{}{
		"00a29def-1ebf-47a3-9021-df0ff7620a2a",
		"22355562-74a8-4b3b-aa9e-b8904148ab81",
		"group-id-3",
		"group-id-4",
		"group-id-5",
	}

	var capturedMethod string
	var capturedPath string
	var capturedBody string
	var capturedContentType string

	// OIDC discovery + Graph API test server
	aServer := new(azureServer)
	aServer.t = t
	aServer.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Write([]byte(strings.Replace(`
				{
					"issuer": "%s",
					"authorization_endpoint": "%s/auth",
					"token_endpoint": "%s/oauth2/v2.0/token",
					"jwks_uri": "%s/certs",
					"userinfo_endpoint": "%s/userinfo"
				}`, "%s", aServer.server.URL, -1)))
		case "/v1.0/me/getMemberObjects":
			capturedMethod = r.Method
			capturedPath = r.URL.Path
			capturedContentType = r.Header.Get("content-type")
			body, _ := io.ReadAll(r.Body)
			capturedBody = string(body)

			resp := azureGroups{Value: expectedGroups}
			gBytes, _ := json.Marshal(resp)
			w.Write(gBytes)
		default:
			t.Fatalf("unexpected path: %q", r.URL.Path)
		}
	}))
	defer aServer.server.Close()

	aCert, err := aServer.getTLSCert()
	require.NoError(t, err)

	b, storage := getBackend(t)
	ctx := context.Background()

	// Configure with fetch_groups enabled
	data := map[string]interface{}{
		"oidc_discovery_url":    aServer.server.URL,
		"oidc_discovery_ca_pem": aCert,
		"oidc_client_id":        "abc",
		"oidc_client_secret":    "def",
		"default_role":          "test",
		"bound_issuer":          "http://vault.example.com/",
		"provider_config": map[string]interface{}{
			"provider":     "azure",
			"fetch_groups": true,
		},
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Set up test role
	data = map[string]interface{}{
		"user_claim":            "email",
		"groups_claim":          "groups",
		"allowed_redirect_uris": []string{"https://example.com"},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp)

	role := &jwtRole{
		GroupsClaim: "groups",
	}

	allClaims := map[string]interface{}{
		"email": "test@example.com",
	}

	// Populate cachedConfig
	config, err := b.(*jwtAuthBackend).config(ctx, storage)
	require.NoError(t, err)

	provider, err := NewProviderConfig(ctx, config, ProviderMap())
	require.NoError(t, err)

	// Override cachedConfig so createCAContext passes through providerCtx.
	// Use a custom RoundTripper to redirect the hardcoded graph.microsoft.com
	// URL to the test server, while preserving path, method, and body.
	backend := b.(*jwtAuthBackend)
	backend.cachedConfig.OIDCDiscoveryCAPEM = ""
	serverTransport := aServer.server.Client().Transport
	targetURL, err := url.Parse(aServer.server.URL)
	require.NoError(t, err)
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			return serverTransport.RoundTrip(req)
		}),
	}
	backend.providerCtx = context.WithValue(context.Background(), oauth2.HTTPClient, client)

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test.access.token"})
	groupsResp, err := backend.fetchGroups(ctx, provider, allClaims, role, tokenSource)

	require.NoError(t, err)
	assert.Equal(t, expectedGroups, groupsResp)

	// Assert the request hit /v1.0/me/getMemberObjects with POST and expected payload
	assert.Equal(t, http.MethodPost, capturedMethod)
	assert.Equal(t, "/v1.0/me/getMemberObjects", capturedPath)
	assert.Equal(t, "application/json", capturedContentType)
	assert.JSONEq(t, `{"securityEnabledOnly": false}`, capturedBody)
}

func TestAzureProvider_FetchGroups_ManyGroups(t *testing.T) {
	// Simulate a user with 450+ groups
	expectedGroups := make([]interface{}, 450)
	for i := 0; i < 450; i++ {
		expectedGroups[i] = fmt.Sprintf("group-id-%d", i)
	}

	var capturedMethod string
	var capturedPath string

	aServer := new(azureServer)
	aServer.t = t
	aServer.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Write([]byte(strings.Replace(`
				{
					"issuer": "%s",
					"authorization_endpoint": "%s/auth",
					"token_endpoint": "%s/oauth2/v2.0/token",
					"jwks_uri": "%s/certs",
					"userinfo_endpoint": "%s/userinfo"
				}`, "%s", aServer.server.URL, -1)))
		case "/v1.0/me/getMemberObjects":
			capturedMethod = r.Method
			capturedPath = r.URL.Path

			resp := azureGroups{Value: expectedGroups}
			gBytes, _ := json.Marshal(resp)
			w.Write(gBytes)
		default:
			t.Fatalf("unexpected path: %q", r.URL.Path)
		}
	}))
	defer aServer.server.Close()

	aCert, err := aServer.getTLSCert()
	require.NoError(t, err)

	b, storage := getBackend(t)
	ctx := context.Background()

	// Configure with fetch_groups enabled
	data := map[string]interface{}{
		"oidc_discovery_url":    aServer.server.URL,
		"oidc_discovery_ca_pem": aCert,
		"oidc_client_id":        "abc",
		"oidc_client_secret":    "def",
		"default_role":          "test",
		"bound_issuer":          "http://vault.example.com/",
		"provider_config": map[string]interface{}{
			"provider":     "azure",
			"fetch_groups": true,
		},
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Set up test role
	data = map[string]interface{}{
		"user_claim":            "email",
		"groups_claim":          "groups",
		"allowed_redirect_uris": []string{"https://example.com"},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp)

	role := &jwtRole{
		GroupsClaim: "groups",
	}

	allClaims := map[string]interface{}{
		"email": "test@example.com",
	}

	config, err := b.(*jwtAuthBackend).config(ctx, storage)
	require.NoError(t, err)

	provider, err := NewProviderConfig(ctx, config, ProviderMap())
	require.NoError(t, err)

	// Redirect the hardcoded graph.microsoft.com URL to the test server
	backend := b.(*jwtAuthBackend)
	backend.cachedConfig.OIDCDiscoveryCAPEM = ""
	serverTransport := aServer.server.Client().Transport
	targetURL, err := url.Parse(aServer.server.URL)
	require.NoError(t, err)
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			return serverTransport.RoundTrip(req)
		}),
	}
	backend.providerCtx = context.WithValue(context.Background(), oauth2.HTTPClient, client)

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test.access.token"})
	groupsResp, err := backend.fetchGroups(ctx, provider, allClaims, role, tokenSource)

	require.NoError(t, err)
	groupsList, ok := groupsResp.([]interface{})
	require.True(t, ok)
	assert.Len(t, groupsList, 450)
	assert.Equal(t, expectedGroups, groupsResp)

	// Assert the request went through the full FetchGroups path
	assert.Equal(t, http.MethodPost, capturedMethod)
	assert.Equal(t, "/v1.0/me/getMemberObjects", capturedPath)
}

func TestAzureProvider_FetchGroups_Disabled(t *testing.T) {
	aServer := newAzureServer(t)
	aCert, err := aServer.getTLSCert()
	require.NoError(t, err)

	b, storage := getBackend(t)
	ctx := context.Background()

	// Configure WITHOUT fetch_groups (default behavior)
	data := map[string]interface{}{
		"oidc_discovery_url":    aServer.server.URL,
		"oidc_discovery_ca_pem": aCert,
		"oidc_client_id":        "abc",
		"oidc_client_secret":    "def",
		"default_role":          "test",
		"bound_issuer":          "http://vault.example.com/",
		"provider_config": map[string]interface{}{
			"provider": "azure",
			// fetch_groups not set, defaults to false
		},
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Set up test role
	data = map[string]interface{}{
		"user_claim":            "email",
		"groups_claim":          "groups",
		"allowed_redirect_uris": []string{"https://example.com"},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp)

	role := &jwtRole{
		GroupsClaim: "groups",
	}

	// Claims WITH groups in token (normal case < 200 groups)
	allClaims := map[string]interface{}{
		"email":  "test@example.com",
		"groups": []interface{}{"inline-group-1", "inline-group-2"},
	}

	config, err := b.(*jwtAuthBackend).config(ctx, storage)
	require.NoError(t, err)

	provider, err := NewProviderConfig(ctx, config, ProviderMap())
	require.NoError(t, err)

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test.access.token"})
	groupsResp, err := b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, role, tokenSource)

	assert.NoError(t, err)
	// Should return groups from claims, not from API
	assert.Equal(t, []interface{}{"inline-group-1", "inline-group-2"}, groupsResp)
}

func TestAzureProvider_FetchGroups_NoTokenSource(t *testing.T) {
	a := &AzureProvider{
		ctx: context.Background(),
		config: AzureProviderConfig{
			FetchGroups: true,
		},
	}

	// Test with nil tokenSource - should fail
	groups, err := a.getAzureGroups("https://graph.microsoft.com/v1.0/me/getMemberObjects", nil)

	assert.EqualError(t, err, "token unavailable to call Microsoft Graph API")
	assert.Nil(t, groups)
}

func TestAzureProvider_GetAzureGroups_ErrorCases(t *testing.T) {
	t.Run("invalid URL", func(t *testing.T) {
		a := &AzureProvider{ctx: context.Background()}
		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"})

		groups, err := a.getAzureGroups("://invalid-url", tokenSource)

		assert.Error(t, err)
		assert.Nil(t, groups)
	})

	t.Run("server returns error status", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "unauthorized"}`))
		}))
		defer server.Close()

		a := &AzureProvider{
			ctx: context.WithValue(context.Background(), oauth2.HTTPClient, server.Client()),
		}
		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"})

		groups, err := a.getAzureGroups(server.URL, tokenSource)

		assert.Error(t, err)
		assert.Nil(t, groups)
		assert.Contains(t, err.Error(), "unauthorized")
	})

	t.Run("server returns invalid JSON", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`not valid json`))
		}))
		defer server.Close()

		a := &AzureProvider{
			ctx: context.WithValue(context.Background(), oauth2.HTTPClient, server.Client()),
		}
		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"})

		groups, err := a.getAzureGroups(server.URL, tokenSource)

		assert.Error(t, err)
		assert.Nil(t, groups)
		assert.Contains(t, err.Error(), "decode")
	})
}

func TestAzureProvider_Initialize(t *testing.T) {
	t.Run("fetch_groups enabled", func(t *testing.T) {
		a := &AzureProvider{}
		jc := &jwtConfig{
			ProviderConfig: map[string]interface{}{
				"provider":     "azure",
				"fetch_groups": true,
			},
		}
		err := a.Initialize(context.Background(), jc)
		assert.NoError(t, err)
		assert.True(t, a.config.FetchGroups)
	})

	t.Run("fetch_groups disabled", func(t *testing.T) {
		a := &AzureProvider{}
		jc := &jwtConfig{
			ProviderConfig: map[string]interface{}{
				"provider":     "azure",
				"fetch_groups": false,
			},
		}
		err := a.Initialize(context.Background(), jc)
		assert.NoError(t, err)
		assert.False(t, a.config.FetchGroups)
	})

	t.Run("fetch_groups not set", func(t *testing.T) {
		a := &AzureProvider{}
		jc := &jwtConfig{
			ProviderConfig: map[string]interface{}{
				"provider": "azure",
			},
		}
		err := a.Initialize(context.Background(), jc)
		assert.NoError(t, err)
		assert.False(t, a.config.FetchGroups) // defaults to false
	})
}

func Test_getClaimSources(t *testing.T) {
	t.Run("normal case", func(t *testing.T) {
		a := &AzureProvider{}
		role := &jwtRole{
			GroupsClaim: "groups",
		}
		allClaims := H{
			claimNamesField: H{
				role.GroupsClaim: "src1",
			},
			claimSourcesField: H{
				"src1": H{
					"endpoint": "/test/endpoint",
				},
			},
		}
		source, err := a.getClaimSource(hclog.Default(), allClaims, role)
		assert.NoError(t, err)
		assert.Equal(t, "/test/endpoint", source)
	})

	t.Run("no _claim_names", func(t *testing.T) {
		a := AzureProvider{}
		role := &jwtRole{
			GroupsClaim: "groups",
		}
		allClaims := H{
			"not_claim_names": "blank",
		}
		source, err := a.getClaimSource(hclog.Default(), allClaims, role)
		assert.Error(t, err)
		assert.Empty(t, source)
	})

	t.Run("no _claim_sources", func(t *testing.T) {
		a := AzureProvider{}
		role := &jwtRole{
			GroupsClaim: "groups",
		}
		allClaims := H{
			claimNamesField: H{
				role.GroupsClaim: "src1",
			},
		}
		source, err := a.getClaimSource(hclog.Default(), allClaims, role)
		assert.Error(t, err)
		assert.Empty(t, source)
	})
}
