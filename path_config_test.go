package jwtauth

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/helper/certutil"
	"github.com/hashicorp/vault/logical"
)

func TestConfig_JWT_Read(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"oidc_issuer_url":        "",
		"oidc_issuer_ca_pem":     "",
		"jwt_validation_pubkeys": []string{testJWTPubKey},
		"bound_issuer":           "http://vault.example.com/",
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

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      nil,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if diff := deep.Equal(resp.Data, data); diff != nil {
		t.Fatalf("Expected did not equal actual: %v", diff)
	}
}

func TestConfig_JWT_Write(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"oidc_issuer_url":        "http://fake.example.com",
		"jwt_validation_pubkeys": []string{testJWTPubKey},
		"bound_issuer":           "http://vault.example.com/",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if !strings.HasPrefix(resp.Error().Error(), "exactly one of") {
		t.Fatalf("got unexpected error: %v", resp.Error())
	}

	delete(data, "oidc_issuer_url")

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	pubkey, err := certutil.ParsePublicKeyPEM([]byte(testJWTPubKey))
	if err != nil {
		t.Fatal(err)
	}

	expected := &jwtConfig{
		ParsedJWTPubKeys:     []interface{}{pubkey},
		JWTValidationPubKeys: []string{testJWTPubKey},
		BoundIssuer:          "http://vault.example.com/",
	}

	conf, err := b.(*jwtAuthBackend).config(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, conf) {
		t.Fatalf("expected did not match actual: expected %#v\n got %#v\n", expected, conf)
	}
}

var testJWTPubKey string = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----`
