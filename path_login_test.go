package jwtauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/hashicorp/vault/logical"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func setupBackend(t *testing.T, oidc bool) (logical.Backend, logical.Storage) {
	b, storage := getBackend(t)

	var data map[string]interface{}
	if oidc {
	} else {
		data = map[string]interface{}{
			"bound_issuer":           "http://vault.example.com/",
			"jwt_validation_pubkeys": ecdsaPubKey,
		}
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	data = map[string]interface{}{
		"bound_subject":   "testsub",
		"bound_audiences": "vault",
		"user_claim":      "user",
		"groups_claim":    "groups",
		"policies":        "test",
		"period":          "3s",
		"ttl":             "1s",
		"num_uses":        12,
		"max_ttl":         "5s",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	return b, storage
}

func getTestJWT(t *testing.T, privKey string, cl jwt.Claims, privateCl interface{}) (string, *ecdsa.PrivateKey) {
	t.Helper()
	var key *ecdsa.PrivateKey
	block, _ := pem.Decode([]byte(privKey))
	if block != nil {
		var err error
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}

	raw, err := jwt.Signed(sig).Claims(cl).Claims(privateCl).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	return raw, key
}

func TestLogin_JWT(t *testing.T) {
	b, storage := setupBackend(t, false)

	// test valid inputs
	{
		cl := jwt.Claims{
			Subject:   "testsub",
			Issuer:    "http://vault.example.com/",
			NotBefore: jwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Audience:  jwt.Audience{"vault", "gloogle"},
		}

		privateCl := struct {
			User   string   `json:"user"`
			Groups []string `json:"groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role":  "plugin-test",
			"token": jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if resp.IsError() {
			t.Fatalf("got error: %v", resp.Error())
		}

		auth := resp.Auth
		switch {
		case len(auth.Policies) != 1 || auth.Policies[0] != "test":
			t.Fatal(auth.Policies)
		case auth.Alias.Name != "jeff":
			t.Fatal(auth.Alias.Name)
		case len(auth.GroupAliases) != 2 || auth.GroupAliases[0].Name != "foo" || auth.GroupAliases[1].Name != "bar":
			t.Fatal(auth.GroupAliases)
		case auth.Period != 3*time.Second:
			t.Fatal(auth.Period)
		case auth.TTL != time.Second:
			t.Fatal(auth.TTL)
		case auth.MaxTTL != 5*time.Second:
			t.Fatal(auth.MaxTTL)
		}
	}

	// test bad signature
	{
		cl := jwt.Claims{
			Subject:   "testsub",
			Issuer:    "http://vault.example.com/",
			NotBefore: jwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Audience:  jwt.Audience{"vault", "gloogle"},
		}

		privateCl := struct {
			User   string   `json:"user"`
			Groups []string `json:"groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, badPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role":  "plugin-test",
			"token": jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatalf("expected error: %v", *resp)
		}
	}

	// test bad issuer
	{
		cl := jwt.Claims{
			Subject:   "testsub",
			Issuer:    "http://fault.example.com/",
			NotBefore: jwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Audience:  jwt.Audience{"vault", "gloogle"},
		}

		privateCl := struct {
			User   string   `json:"user"`
			Groups []string `json:"groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role":  "plugin-test",
			"token": jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatalf("expected error: %v", *resp)
		}
	}

	// test bad audience
	{
		cl := jwt.Claims{
			Subject:   "testsub",
			Issuer:    "http://vault.example.com/",
			NotBefore: jwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Audience:  jwt.Audience{"fault", "gloogle"},
		}

		privateCl := struct {
			User   string   `json:"user"`
			Groups []string `json:"groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role":  "plugin-test",
			"token": jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatalf("expected error: %v", *resp)
		}
	}

	// test bad subject
	{
		cl := jwt.Claims{
			Subject:   "testsup",
			Issuer:    "http://vault.example.com/",
			NotBefore: jwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
			Audience:  jwt.Audience{"vault", "gloogle"},
		}

		privateCl := struct {
			User   string   `json:"user"`
			Groups []string `json:"groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role":  "plugin-test",
			"token": jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatalf("expected error: %v", *resp)
		}
	}

	// test bad expiry (using auto expiry)
	{
		cl := jwt.Claims{
			Subject:   "testsub",
			Issuer:    "http://vault.example.com/",
			NotBefore: jwt.NewNumericDate(time.Now().Add(-5 * time.Hour)),
			Audience:  jwt.Audience{"vault", "gloogle"},
		}

		privateCl := struct {
			User   string   `json:"user"`
			Groups []string `json:"groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role":  "plugin-test",
			"token": jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatalf("expected error: %v", *resp)
		}
	}

	// test bad notbefore (using auto)
	{
		cl := jwt.Claims{
			Subject:  "testsub",
			Issuer:   "http://vault.example.com/",
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Hour)),
			Audience: jwt.Audience{"vault", "gloogle"},
		}

		privateCl := struct {
			User   string   `json:"user"`
			Groups []string `json:"groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role":  "plugin-test",
			"token": jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatalf("expected error: %v", *resp)
		}
	}

	// test auto notbefore from issue time
	{
		cl := jwt.Claims{
			Subject:  "testsub",
			Issuer:   "http://vault.example.com/",
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Second)),
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-5 * time.Hour)),
			Audience: jwt.Audience{"vault", "gloogle"},
		}

		privateCl := struct {
			User   string   `json:"user"`
			Groups []string `json:"groups"`
		}{
			"jeff",
			[]string{"foo", "bar"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, privateCl)

		data := map[string]interface{}{
			"role":  "plugin-test",
			"token": jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if resp.IsError() {
			t.Fatalf("unexpected error: %v", resp.Error())
		}
	}

	// test missing user value
	{
		cl := jwt.Claims{
			Subject:  "testsub",
			Issuer:   "http://vault.example.com/",
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Second)),
			Audience: jwt.Audience{"vault", "gloogle"},
		}

		jwtData, _ := getTestJWT(t, ecdsaPrivKey, cl, struct{}{})

		data := map[string]interface{}{
			"role":  "plugin-test",
			"token": jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("got nil response")
		}
		if !resp.IsError() {
			t.Fatalf("expected error: %v", *resp)
		}
	}
	// test bad role name
	{
		jwtData, _ := getTestJWT(t, ecdsaPrivKey, jwt.Claims{}, struct{}{})

		data := map[string]interface{}{
			"role":  "plugin-test-bad",
			"token": jwtData,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
		if resp.Error().Error() != "role could not be found" {
			t.Fatalf("unexpected error: %s", resp.Error())
		}
	}
}

const (
	ecdsaPrivKey string = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKfldwWLPYsHjRL9EVTsjSbzTtcGRu6icohNfIqcb6A+oAoGCCqGSM49
AwEHoUQDQgAE4+SFvPwOy0miy/FiTT05HnwjpEbSq+7+1q9BFxAkzjgKnlkXk5qx
hzXQvRmS4w9ZsskoTZtuUI+XX7conJhzCQ==
-----END EC PRIVATE KEY-----`

	ecdsaPubKey string = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4+SFvPwOy0miy/FiTT05HnwjpEbS
q+7+1q9BFxAkzjgKnlkXk5qxhzXQvRmS4w9ZsskoTZtuUI+XX7conJhzCQ==
-----END PUBLIC KEY-----`

	badPrivKey string = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILTAHJm+clBKYCrRDc74Pt7uF7kH+2x2TdL5cH23FEcsoAoGCCqGSM49
AwEHoUQDQgAE+C3CyjVWdeYtIqgluFJlwZmoonphsQbj9Nfo5wrEutv+3RTFnDQh
vttUajcFAcl4beR+jHFYC00vSO4i5jZ64g==
-----END EC PRIVATE KEY-----`
)
