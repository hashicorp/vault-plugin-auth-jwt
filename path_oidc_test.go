package jwtauth

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-sockaddr"

	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestOIDC_AuthURL(t *testing.T) {
	b, storage := getBackend(t)

	// Configure backend
	data := map[string]interface{}{
		"oidc_discovery_url":    "https://team-vault.auth0.com/",
		"oidc_discovery_ca_pem": "",
		"oidc_client_id":        "abc",
		"oidc_client_secret":    "def",
		"default_role":          "test",
		"bound_issuer":          "http://vault.example.com/",
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
		"bound_audiences":       "vault",
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

	t.Run("normal case", func(t *testing.T) {
		t.Parallel()

		// normal cases, both passing the role name explicitly and relying on the default
		for _, rolename := range []string{"test", ""} {
			data := map[string]interface{}{
				"role":         rolename,
				"redirect_uri": "https://example.com",
			}
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "oidc/auth_url",
				Storage:   storage,
				Data:      data,
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%v resp:%#v\n", err, resp)
			}

			authURL := resp.Data["auth_url"].(string)

			expected := []string{
				`client_id=abc`,
				`https://team-vault\.auth0\.com/authorize`,
				`scope=openid`,
				`nonce=\w{27}`,
				`state=\w{27}`,
				`redirect_uri=https%3A%2F%2Fexample.com`,
				`response_type=code`,
				`scope=openid`,
			}

			for _, test := range expected {
				matched, err := regexp.MatchString(test, authURL)
				if err != nil {
					t.Fatal(err)
				}
				if !matched {
					t.Fatalf("expected to match regex: %s", test)
				}
			}
		}
	})

	t.Run("missing role", func(t *testing.T) {
		t.Parallel()

		data := map[string]interface{}{
			"role":         "not_a_role",
			"redirect_uri": "https://example.com",
		}
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "oidc/auth_url",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}

		if !resp.IsError() {
			t.Fatalf("expected error response, got: %v", resp)
		}
	})

	// create limited role with restricted redirect_uris
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/limited_uris",
		Storage:   storage,
		Data: map[string]interface{}{
			"role_type":             "oidc",
			"user_claim":            "email",
			"bound_audiences":       "vault",
			"allowed_redirect_uris": []string{"https://zombo.com", "https://example.com"},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v\n", err, resp)
	}

	t.Run("valid redirect_uri", func(t *testing.T) {
		t.Parallel()

		data := map[string]interface{}{
			"role":         "limited_uris",
			"redirect_uri": "https://example.com",
		}
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "oidc/auth_url",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v\n", err, resp)
		}

		authURL := resp.Data["auth_url"].(string)
		escapedRedirect := url.QueryEscape("https://example.com")
		if !strings.Contains(authURL, escapedRedirect) {
			t.Fatalf(`didn't find expected redirect_uri '%s' in: %s`, escapedRedirect, authURL)
		}
	})

	t.Run("invalid redirect_uri", func(t *testing.T) {
		t.Parallel()

		data := map[string]interface{}{
			"role":         "limited_uris",
			"redirect_uri": "http://bitc0in-4-less.cx",
		}
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "oidc/auth_url",
			Storage:   storage,
			Data:      data,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v", err, resp)
		}

		authURL := resp.Data["auth_url"].(string)
		if authURL != "" {
			t.Fatalf(`expected: "", actual: %s`, authURL)
		}
	})
}

func TestOIDC_Callback(t *testing.T) {
	t.Run("successful login", func(t *testing.T) {

		// run test with and without bound_cidrs configured
		for _, useBoundCIDRs := range []bool{false, true} {
			b, storage, s := getBackendAndServer(t, useBoundCIDRs)
			defer s.server.Close()

			// get auth_url
			data := map[string]interface{}{
				"role":         "test",
				"redirect_uri": "https://example.com",
			}
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "oidc/auth_url",
				Storage:   storage,
				Data:      data,
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%v resp:%#v\n", err, resp)
			}

			authURL := resp.Data["auth_url"].(string)

			state := getQueryParam(t, authURL, "state")
			nonce := getQueryParam(t, authURL, "nonce")

			// set provider claims that will be returned by the mock server
			s.customClaims = sampleClaims(nonce)

			// set mock provider's expected code
			s.code = "abc"

			// invoke the callback, which will in to try to exchange the code
			// with the mock provider.
			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "oidc/callback",
				Storage:   storage,
				Data: map[string]interface{}{
					"state": state,
					"code":  "abc",
				},
				Connection: &logical.Connection{
					RemoteAddr: "127.0.0.42",
				},
			}

			resp, err = b.HandleRequest(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}

			expected := &logical.Auth{
				LeaseOptions: logical.LeaseOptions{
					Renewable: true,
					TTL:       3 * time.Minute,
					MaxTTL:    5 * time.Minute,
				},
				InternalData: map[string]interface{}{
					"role": "test",
				},
				DisplayName: "bob@example.com",
				Alias: &logical.Alias{
					Name: "bob@example.com",
					Metadata: map[string]string{
						"color": "green",
						"size":  "medium",
					},
				},
				GroupAliases: []*logical.Alias{
					{Name: "a"},
					{Name: "b"},
				},
				Metadata: map[string]string{
					"role":  "test",
					"color": "green",
					"size":  "medium",
				},
				NumUses: 10,
			}
			if useBoundCIDRs {
				sock, err := sockaddr.NewSockAddr("127.0.0.42")
				if err != nil {
					t.Fatal(err)
				}
				expected.BoundCIDRs = []*sockaddr.SockAddrMarshaler{{SockAddr: sock}}
			}

			auth := resp.Auth

			if !reflect.DeepEqual(auth, expected) {
				t.Fatalf("expected: %v, auth: %v", expected, resp)
			}
		}
	})

	t.Run("failed login - bad nonce", func(t *testing.T) {
		b, storage, s := getBackendAndServer(t, false)
		defer s.server.Close()

		// get auth_url
		data := map[string]interface{}{
			"role":         "test",
			"redirect_uri": "https://example.com",
		}
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "oidc/auth_url",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v\n", err, resp)
		}

		authURL := resp.Data["auth_url"].(string)

		state := getQueryParam(t, authURL, "state")

		s.customClaims = sampleClaims("bad nonce")

		// set mock provider's expected code
		s.code = "abc"

		// invoke the callback, which will in to try to exchange the code
		// with the mock provider.
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "oidc/callback",
			Storage:   storage,
			Data: map[string]interface{}{
				"state": state,
				"code":  "abc",
			},
		}

		resp, err = b.HandleRequest(context.Background(), req)

		if err != nil {
			t.Fatal(err)
		}
		if !resp.IsError() {
			t.Fatalf("expected error response, got: %v", resp.Data)
		}
	})

	t.Run("failed login - bound claim mismatch", func(t *testing.T) {
		b, storage, s := getBackendAndServer(t, false)
		defer s.server.Close()

		// get auth_url
		data := map[string]interface{}{
			"role":         "test",
			"redirect_uri": "https://example.com",
		}
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "oidc/auth_url",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v\n", err, resp)
		}

		authURL := resp.Data["auth_url"].(string)

		state := getQueryParam(t, authURL, "state")
		nonce := getQueryParam(t, authURL, "nonce")

		s.customClaims = sampleClaims(nonce)
		s.customClaims["sk"] = "43" // the pre-configured role has a bound claim of "sk"=="42"

		// set mock provider's expected code
		s.code = "abc"

		// invoke the callback, which will in to try to exchange the code
		// with the mock provider.
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "oidc/callback",
			Storage:   storage,
			Data: map[string]interface{}{
				"state": state,
				"code":  "abc",
			},
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !resp.IsError() {
			t.Fatalf("expected error response, got: %v", resp.Data)
		}
	})

	t.Run("missing state", func(t *testing.T) {
		b, storage, s := getBackendAndServer(t, false)
		defer s.server.Close()

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "oidc/callback",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil || !strings.Contains(resp.Error().Error(), "Expired or missing OAuth state") {
			t.Fatalf("expected OAuth state error response, got: %#v", resp)
		}
	})

	t.Run("unknown state", func(t *testing.T) {
		b, storage, s := getBackendAndServer(t, false)
		defer s.server.Close()

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "oidc/callback",
			Storage:   storage,
			Data: map[string]interface{}{
				"state": "not_a_state",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil || !strings.Contains(resp.Error().Error(), "Expired or missing OAuth state") {
			t.Fatalf("expected OAuth state error response, got: %#v", resp)
		}
	})

	t.Run("valid state, missing code", func(t *testing.T) {
		b, storage, s := getBackendAndServer(t, false)
		defer s.server.Close()

		// get auth_url
		data := map[string]interface{}{
			"role":         "test",
			"redirect_uri": "https://example.com",
		}
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "oidc/auth_url",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v\n", err, resp)
		}

		authURL := resp.Data["auth_url"].(string)
		state := getQueryParam(t, authURL, "state")

		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "oidc/callback",
			Storage:   storage,
			Data: map[string]interface{}{
				"state": state,
			},
		}
		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}

		if resp == nil || !strings.Contains(resp.Error().Error(), "No code or id_token received") {
			t.Fatalf("expected OAuth core error response, got: %#v", resp)
		}
	})

	t.Run("failed code exchange", func(t *testing.T) {
		b, storage, s := getBackendAndServer(t, false)
		defer s.server.Close()

		// get auth_url
		data := map[string]interface{}{
			"role":         "test",
			"redirect_uri": "https://example.com",
		}
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "oidc/auth_url",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v\n", err, resp)
		}

		authURL := resp.Data["auth_url"].(string)
		state := getQueryParam(t, authURL, "state")

		// set mock provider's expected code
		s.code = "abc"

		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "oidc/callback",
			Storage:   storage,
			Data: map[string]interface{}{
				"state": state,
				"code":  "wrong_code",
			},
		}
		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}

		if resp == nil || !strings.Contains(resp.Error().Error(), "cannot fetch token") {
			t.Fatalf("expected code exchange error response, got: %#v", resp)
		}
	})

	t.Run("no response from provider", func(t *testing.T) {
		b, storage, s := getBackendAndServer(t, false)

		// get auth_url
		data := map[string]interface{}{
			"role":         "test",
			"redirect_uri": "https://example.com",
		}
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "oidc/auth_url",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v\n", err, resp)
		}

		authURL := resp.Data["auth_url"].(string)
		state := getQueryParam(t, authURL, "state")

		// close the server prematurely
		s.server.Close()
		s.code = "abc"

		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "oidc/callback",
			Storage:   storage,
			Data: map[string]interface{}{
				"state": state,
				"code":  "abc",
			},
		}
		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}

		if resp == nil || !strings.Contains(resp.Error().Error(), "connection refused") {
			t.Fatalf("expected code exchange error response, got: %#v", resp)
		}
	})

	t.Run("test bad address", func(t *testing.T) {
		b, storage, s := getBackendAndServer(t, true)
		defer s.server.Close()

		s.code = "abc"

		// get auth_url
		data := map[string]interface{}{
			"role":         "test",
			"redirect_uri": "https://example.com",
		}
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "oidc/auth_url",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v\n", err, resp)
		}

		authURL := resp.Data["auth_url"].(string)
		state := getQueryParam(t, authURL, "state")

		// request with invalid CIDR, which should fail
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "oidc/callback",
			Storage:   storage,
			Data: map[string]interface{}{
				"state": state,
				"code":  "abc",
			},
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.99",
			},
		}
		resp, err = b.HandleRequest(context.Background(), req)
		if err != logical.ErrPermissionDenied {
			t.Fatal(err)
		}
	})

	t.Run("test invalid client_id", func(t *testing.T) {
		b, storage, s := getBackendAndServer(t, false)
		defer s.server.Close()

		s.code = "abc"
		s.clientID = "not_gonna_match"

		// get auth_url
		data := map[string]interface{}{
			"role":         "test",
			"redirect_uri": "https://example.com",
		}
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "oidc/auth_url",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v\n", err, resp)
		}

		authURL := resp.Data["auth_url"].(string)
		state := getQueryParam(t, authURL, "state")
		nonce := getQueryParam(t, authURL, "nonce")

		// set provider claims that will be returned by the mock server
		s.customClaims = sampleClaims(nonce)

		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "oidc/callback",
			Storage:   storage,
			Data: map[string]interface{}{
				"state": state,
				"code":  "abc",
			},
		}
		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("nil response")
		}

		if !resp.IsError() || !strings.Contains(resp.Error().Error(), `error validating signature: oidc: expected audience "abc"`) {
			t.Fatalf("expected invalid client_id error, got : %v", *resp)
		}
	})

	t.Run("client_nonce", func(t *testing.T) {
		b, storage, s := getBackendAndServer(t, false)
		defer s.server.Close()

		// General behavior is that if a client_nonce is provided during the authURL phase
		// it must be provided during the callback phase.
		tests := map[string]struct {
			authURLNonce  string
			callbackNonce string
			errExpected   bool
		}{
			"default, no nonces": {
				errExpected: false,
			},
			"matching nonces": {
				authURLNonce:  "abc123",
				callbackNonce: "abc123",
				errExpected:   false,
			},
			"mismatched nonces": {
				authURLNonce:  "abc123",
				callbackNonce: "abc123xyz",
				errExpected:   true,
			},
			"missing nonce": {
				authURLNonce: "abc123",
				errExpected:  true,
			},
			"ignore unexpected callback nonce": {
				callbackNonce: "abc123",
				errExpected:   false,
			},
		}

		for name, test := range tests {
			// get auth_url
			data := map[string]interface{}{
				"role":         "test",
				"redirect_uri": "https://example.com",
				"client_nonce": test.authURLNonce,
			}
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "oidc/auth_url",
				Storage:   storage,
				Data:      data,
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%v resp:%#v\n", err, resp)
			}

			authURL := resp.Data["auth_url"].(string)

			state := getQueryParam(t, authURL, "state")
			nonce := getQueryParam(t, authURL, "nonce")

			// set provider claims that will be returned by the mock server
			s.customClaims = sampleClaims(nonce)

			// set mock provider's expected code
			s.code = "abc"

			// invoke the callback, which will try to exchange the code
			// with the mock provider.
			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "oidc/callback",
				Storage:   storage,
				Data: map[string]interface{}{
					"state":        state,
					"code":         "abc",
					"client_nonce": test.callbackNonce,
				},
			}

			resp, err = b.HandleRequest(context.Background(), req)

			if err != nil {
				t.Fatal(err)
			}

			if test.errExpected != resp.IsError() {
				t.Fatalf("%s: unexpected error response, expected: %v,  got: %v", name, test.errExpected, resp.Data)
			}
		}
	})
}

// oidcProvider is local server the mocks the basis endpoints used by the
// OIDC callback process.
type oidcProvider struct {
	t            *testing.T
	server       *httptest.Server
	clientID     string
	clientSecret string
	code         string
	customClaims map[string]interface{}
}

func newOIDCProvider(t *testing.T) *oidcProvider {
	o := new(oidcProvider)
	o.t = t
	o.server = httptest.NewTLSServer(o)

	return o
}

func (o *oidcProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		w.Write([]byte(strings.Replace(`
			{
				"issuer": "%s",
				"authorization_endpoint": "%s/auth",
				"token_endpoint": "%s/token",
				"jwks_uri": "%s/certs",
				"userinfo_endpoint": "%s/userinfo"
			}`, "%s", o.server.URL, -1)))
	case "/certs":
		a := getTestJWKS(o.t, ecdsaPubKey)
		w.Write(a)
	case "/certs_missing":
		w.WriteHeader(404)
	case "/certs_invalid":
		w.Write([]byte("It's not a keyset!"))
	case "/token":
		code := r.FormValue("code")

		if code != o.code {
			w.WriteHeader(401)
			break
		}

		stdClaims := jwt.Claims{
			Subject:   "r3qXcK2bix9eFECzsU3Sbmh0K16fatW6@clients",
			Issuer:    o.server.URL,
			NotBefore: jwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Second)),
			Audience:  jwt.Audience{o.clientID},
		}
		jwtData, _ := getTestJWT(o.t, ecdsaPrivKey, stdClaims, o.customClaims)
		w.Write([]byte(fmt.Sprintf(`
			{
				"access_token":"%s",
				"id_token":"%s"
			}`,
			jwtData,
			jwtData,
		)))
	case "/userinfo":
		w.Write([]byte(`
			{
				"color":"red",
				"temperature":"76"
			}`))

	default:
		o.t.Fatalf("unexpected path: %q", r.URL.Path)
	}
}

// getTLSCert returns the certificate for this provider in PEM format
func (o *oidcProvider) getTLSCert() (string, error) {
	cert := o.server.Certificate()
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

func getQueryParam(t *testing.T, inputURL, param string) string {
	t.Helper()

	m, err := url.ParseQuery(inputURL)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := m[param]
	if !ok {
		t.Fatalf("query param %q not found", param)
	}
	return v[0]
}

// getTestJWKS converts a pem-encoded public key into JWKS data suitable
// for a verification endpoint response
func getTestJWKS(t *testing.T, pubKey string) []byte {
	t.Helper()

	block, _ := pem.Decode([]byte(pubKey))
	if block == nil {
		t.Fatal("unable to decode public key")
	}
	input := block.Bytes

	pub, err := x509.ParsePKIXPublicKey(input)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{
		Key: pub,
	}
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	data, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func TestOIDC_ValidRedirect(t *testing.T) {
	tests := []struct {
		uri      string
		allowed  []string
		expected bool
	}{
		// valid
		{"https://example.com", []string{"https://example.com"}, true},
		{"https://example.com:5000", []string{"a", "b", "https://example.com:5000"}, true},
		{"https://example.com/a/b/c", []string{"a", "b", "https://example.com/a/b/c"}, true},
		{"https://localhost:9000", []string{"a", "b", "https://localhost:5000"}, true},
		{"https://127.0.0.1:9000", []string{"a", "b", "https://127.0.0.1:5000"}, true},
		{"https://[::1]:9000", []string{"a", "b", "https://[::1]:5000"}, true},
		{"https://[::1]:9000/x/y?r=42", []string{"a", "b", "https://[::1]:5000/x/y?r=42"}, true},

		// invalid
		{"https://example.com", []string{}, false},
		{"http://example.com", []string{"a", "b", "https://example.com"}, false},
		{"https://example.com:9000", []string{"a", "b", "https://example.com:5000"}, false},
		{"https://[::2]:9000", []string{"a", "b", "https://[::2]:5000"}, false},
		{"https://localhost:5000", []string{"a", "b", "https://127.0.0.1:5000"}, false},
		{"https://localhost:5000", []string{"a", "b", "https://127.0.0.1:5000"}, false},
		{"https://localhost:5000", []string{"a", "b", "http://localhost:5000"}, false},
		{"https://[::1]:5000/x/y?r=42", []string{"a", "b", "https://[::1]:5000/x/y?r=43"}, false},
	}
	for _, test := range tests {
		if validRedirect(test.uri, test.allowed) != test.expected {
			t.Fatalf("Fail on %s/%v. Expected: %t", test.uri, test.allowed, test.expected)
		}
	}
}

func getBackendAndServer(t *testing.T, boundCIDRs bool) (logical.Backend, logical.Storage, *oidcProvider) {
	b, storage := getBackend(t)
	s := newOIDCProvider(t)
	s.clientID = "abc"
	s.clientSecret = "def"

	cert, err := s.getTLSCert()
	if err != nil {
		t.Fatal(err)
	}

	// Configure backend
	data := map[string]interface{}{
		"oidc_discovery_url":    s.server.URL,
		"oidc_client_id":        "abc",
		"oidc_client_secret":    "def",
		"oidc_discovery_ca_pem": cert,
		"default_role":          "test",
		"bound_issuer":          "http://vault.example.com/",
		"jwt_supported_algs":    []string{"ES256"},
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
		"allowed_redirect_uris": []string{"https://example.com"},
		"claim_mappings": map[string]string{
			"COLOR":        "color",
			"/nested/Size": "size",
		},
		"groups_claim":   "/nested/Groups",
		"token_ttl":      "3m",
		"token_num_uses": 10,
		"max_ttl":        "5m",
		"bound_claims": map[string]interface{}{
			"password":            "foo",
			"sk":                  "42",
			"/nested/secret_code": "bar",
			"temperature":         "76",
		},
	}

	if boundCIDRs {
		data["bound_cidrs"] = "127.0.0.42"
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

	return b, storage, s
}

func sampleClaims(nonce string) map[string]interface{} {
	return map[string]interface{}{
		"nonce": nonce,
		"email": "bob@example.com",
		"COLOR": "green",
		"sk":    "42",
		"nested": map[string]interface{}{
			"Size":        "medium",
			"Groups":      []string{"a", "b"},
			"secret_code": "bar",
		},
		"password": "foo",
	}
}

func TestParseMount(t *testing.T) {
	if result := parseMount("https://example.com/v1/auth/oidc"); result != "oidc" {
		t.Fatalf("unexpected result: %s", result)
	}
	if result := parseMount("https://example.com/v1/auth/oidc/foo"); result != "oidc" {
		t.Fatalf("unexpected result: %s", result)
	}
	if result := parseMount("https://example.com/v1/auth/oidc/foo/a/b/c"); result != "oidc" {
		t.Fatalf("unexpected result: %s", result)
	}
}
