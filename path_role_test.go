package jwtauth

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-test/deep"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

func getBackend(t *testing.T) (logical.Backend, logical.Storage) {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),

		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: &logical.InmemStorage{},
	}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}

func TestPath_Create(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"role_type":       "jwt",
		"bound_subject":   "testsub",
		"bound_audiences": "vault",
		"user_claim":      "user",
		"groups_claim":    "groups",
		"bound_cidrs":     "127.0.0.1/8",
		"policies":        "test",
		"period":          "3s",
		"ttl":             "1s",
		"num_uses":        12,
		"max_ttl":         "5s",
	}

	expectedSockAddr, err := sockaddr.NewSockAddr("127.0.0.1/8")
	if err != nil {
		t.Fatal(err)
	}

	expected := &jwtRole{
		RoleType:            "jwt",
		Policies:            []string{"test"},
		Period:              3 * time.Second,
		BoundSubject:        "testsub",
		BoundAudiences:      []string{"vault"},
		UserClaim:           "user",
		GroupsClaim:         "groups",
		TTL:                 1 * time.Second,
		MaxTTL:              5 * time.Second,
		ExpirationLeeway:    0,
		NotBeforeLeeway:     0,
		ClockSkewLeeway:     0,
		NumUses:             12,
		BoundCIDRs:          []*sockaddr.SockAddrMarshaler{{SockAddr: expectedSockAddr}},
		AllowedRedirectURIs: []string(nil),
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	actual, err := b.(*jwtAuthBackend).role(context.Background(), storage, "plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("Unexpected role data: expected %#v\n got %#v\n", expected, actual)
	}

	// Test no user claim
	data = map[string]interface{}{
		"policies": "test",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test2",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && !resp.IsError() {
		t.Fatalf("expected error")
	}
	if resp.Error().Error() != "a user claim must be defined on the role" {
		t.Fatalf("unexpected err: %v", resp)
	}

	// Test no binding
	data = map[string]interface{}{
		"role_type":  "jwt",
		"user_claim": "user",
		"policies":   "test",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test3",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && !resp.IsError() {
		t.Fatalf("expected error")
	}
	if !strings.HasPrefix(resp.Error().Error(), "must have at least one bound constraint") {
		t.Fatalf("unexpected err: %v", resp)
	}

	// Test has bound subject
	data = map[string]interface{}{
		"role_type":     "jwt",
		"user_claim":    "user",
		"policies":      "test",
		"bound_subject": "testsub",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test4",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("did not expect error")
	}

	// Test has audience
	data = map[string]interface{}{
		"role_type":       "jwt",
		"user_claim":      "user",
		"policies":        "test",
		"bound_audiences": "vault",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test5",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("did not expect error")
	}

	// Test has cidr
	data = map[string]interface{}{
		"role_type":   "jwt",
		"user_claim":  "user",
		"policies":    "test",
		"bound_cidrs": "127.0.0.1/8",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test6",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("did not expect error")
	}

	// Test has bound claims
	data = map[string]interface{}{
		"role_type":  "jwt",
		"user_claim": "user",
		"policies":   "test",
		"bound_claims": map[string]interface{}{
			"foo": 10,
			"bar": "baz",
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test7",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("did not expect error")
	}

	// Test has expiration, not before custom leeways
	data = map[string]interface{}{
		"role_type":         "jwt",
		"user_claim":        "user",
		"policies":          "test",
		"expiration_leeway": "5s",
		"not_before_leeway": "5s",
		"clock_skew_leeway": "5s",
		"bound_claims": map[string]interface{}{
			"foo": 10,
			"bar": "baz",
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test8",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("did not expect error:%s", resp.Error().Error())
	}

	actual, err = b.(*jwtAuthBackend).role(context.Background(), storage, "test8")
	if err != nil {
		t.Fatal(err)
	}

	expectedDuration := "5s"
	if actual.ExpirationLeeway.String() != expectedDuration {
		t.Fatalf("expiration_leeway - expected: %s, got: %s", expectedDuration, actual.ExpirationLeeway)
	}

	if actual.NotBeforeLeeway.String() != expectedDuration {
		t.Fatalf("not_before_leeway - expected: %s, got: %s", expectedDuration, actual.NotBeforeLeeway)
	}

	if actual.ClockSkewLeeway.String() != expectedDuration {
		t.Fatalf("clock_skew_leeway - expected: %s, got: %s", expectedDuration, actual.ClockSkewLeeway)
	}

	// Test disabling clock skew leeway default
	data = map[string]interface{}{
		"role_type":         "jwt",
		"user_claim":        "user",
		"policies":          "test",
		"clock_skew_leeway": "0",
		"bound_claims": map[string]interface{}{
			"foo": 10,
			"bar": "baz",
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test9",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("did not expect error:%s", resp.Error().Error())
	}

	actual, err = b.(*jwtAuthBackend).role(context.Background(), storage, "test9")
	if err != nil {
		t.Fatal(err)
	}

	if actual.ClockSkewLeeway != 0 {
		t.Fatalf("clock_skew_leeway - expected: 0, got: %v", actual.ClockSkewLeeway)
	}
}

func TestPath_OIDCCreate(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"bound_audiences": "vault",
		"bound_claims": map[string]interface{}{
			"foo": 10,
			"bar": "baz",
		},
		"oidc_scopes":           []string{"email", "profile"},
		"allowed_redirect_uris": []string{"https://example.com", "http://localhost:8250"},
		"claim_mappings": map[string]string{
			"foo": "a",
			"bar": "b",
		},
		"user_claim":        "user",
		"groups_claim":      "groups",
		"policies":          "test",
		"period":            "3s",
		"ttl":               "1s",
		"num_uses":          12,
		"max_ttl":           "5s",
		"expiration_leeway": "300s",
		"not_before_leeway": "300s",
		"clock_skew_leeway": "1s",
	}

	expected := &jwtRole{
		RoleType:       "oidc",
		Policies:       []string{"test"},
		Period:         3 * time.Second,
		BoundAudiences: []string{"vault"},
		BoundClaims: map[string]interface{}{
			"foo": json.Number("10"),
			"bar": "baz",
		},
		AllowedRedirectURIs: []string{"https://example.com", "http://localhost:8250"},
		ClaimMappings: map[string]string{
			"foo": "a",
			"bar": "b",
		},
		OIDCScopes:       []string{"email", "profile"},
		UserClaim:        "user",
		GroupsClaim:      "groups",
		TTL:              1 * time.Second,
		MaxTTL:           5 * time.Second,
		ExpirationLeeway: 300 * time.Second,
		NotBeforeLeeway:  300 * time.Second,
		ClockSkewLeeway:  1 * time.Second,
		NumUses:          12,
	}

	// test both explicit and default role_type
	for _, roleType := range []string{"", "oidc"} {
		data["role_type"] = roleType
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/plugin-test",
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}
		actual, err := b.(*jwtAuthBackend).role(context.Background(), storage, "plugin-test")
		if err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(expected, actual); diff != nil {
			t.Fatal(diff)
		}
	}

	// Test invalid reserved metadata key 'role'
	data["claim_mappings"] = map[string]string{
		"foo":        "a",
		"some_claim": "role",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test2",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && !resp.IsError() {
		t.Fatalf("expected error")
	}
	if !strings.Contains(resp.Error().Error(), `metadata key "role" is reserved`) {
		t.Fatalf("unexpected err: %v", resp)
	}

	// Test invalid duplicate metadata destination
	data["claim_mappings"] = map[string]string{
		"foo": "a",
		"bar": "a",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test2",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && !resp.IsError() {
		t.Fatalf("expected error")
	}
	if !strings.Contains(resp.Error().Error(), `multiple keys are mapped to metadata key "a"`) {
		t.Fatalf("unexpected err: %v", resp)
	}

	// Test custom expiration_leeway and not_before_leeway values
	delete(data, "some_claim")
	data = map[string]interface{}{
		"user_claim":        "user",
		"expiration_leeway": "5s",
		"not_before_leeway": "5s",
		"bound_claims": map[string]interface{}{
			"foo": "a",
			"bar": "b",
		},
		"allowed_redirect_uris": []string{"https://example.com", "http://localhost:8250"},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test3",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error: %s", resp.Error().Error())
	}

	actual, err := b.(*jwtAuthBackend).role(context.Background(), storage, "test3")
	if err != nil {
		t.Fatal(err)
	}

	expectedDuration := "5s"
	if actual.ExpirationLeeway.String() != expectedDuration {
		t.Fatalf("expiration_leeway - expected: %s, got: %s", expectedDuration, actual.ExpirationLeeway)
	}

	if actual.NotBeforeLeeway.String() != expectedDuration {
		t.Fatalf("not_before_leeway - expected: %s, got: %s", expectedDuration, actual.NotBeforeLeeway)
	}
}

func TestPath_Read(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"role_type":             "jwt",
		"bound_subject":         "testsub",
		"bound_audiences":       "vault",
		"allowed_redirect_uris": []string{"http://127.0.0.1"},
		"oidc_scopes":           []string{"email", "profile"},
		"user_claim":            "user",
		"groups_claim":          "groups",
		"bound_cidrs":           "127.0.0.1/8",
		"policies":              "test",
		"period":                "3s",
		"ttl":                   "1s",
		"num_uses":              12,
		"max_ttl":               "5s",
		"expiration_leeway":     "500s",
		"not_before_leeway":     "500s",
		"clock_skew_leeway":     "100s",
	}

	expected := map[string]interface{}{
		"role_type":             "jwt",
		"bound_claims":          map[string]interface{}(nil),
		"claim_mappings":        map[string]string(nil),
		"bound_subject":         "testsub",
		"bound_audiences":       []string{"vault"},
		"allowed_redirect_uris": []string{"http://127.0.0.1"},
		"oidc_scopes":           []string{"email", "profile"},
		"user_claim":            "user",
		"groups_claim":          "groups",
		"policies":              []string{"test"},
		"period":                int64(3),
		"ttl":                   int64(1),
		"num_uses":              12,
		"max_ttl":               int64(5),
		"expiration_leeway":     int64(500),
		"not_before_leeway":     int64(500),
		"clock_skew_leeway":     int64(100),
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	readTest := func() {
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "role/plugin-test",
			Storage:   storage,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if resp.Data["bound_cidrs"].([]*sockaddr.SockAddrMarshaler)[0].String() != "127.0.0.1/8" {
			t.Fatal("unexpected bound cidrs")
		}
		delete(resp.Data, "bound_cidrs")
		if diff := deep.Equal(expected, resp.Data); diff != nil {
			t.Fatal(diff)
		}
	}

	// Run read test for normal case
	readTest()

	// Remove the 'role_type' parameter in stored role to simulate a legacy role
	rolePath := rolePrefix + "plugin-test"
	raw, err := storage.Get(context.Background(), rolePath)

	var role map[string]interface{}
	if err := raw.DecodeJSON(&role); err != nil {
		t.Fatal(err)
	}
	delete(role, "role_type")
	entry, err := logical.StorageEntryJSON(rolePath, role)
	if err != nil {
		t.Fatal(err)
	}

	if err = req.Storage.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	// Run read test for "upgrade" case. The legacy role is not changed in storage, but
	// reads will populate the `role_type` with "jwt".
	readTest()
}

func TestPath_Delete(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"role_type":         "jwt",
		"bound_subject":     "testsub",
		"bound_audiences":   "vault",
		"user_claim":        "user",
		"groups_claim":      "groups",
		"bound_cidrs":       "127.0.0.1/8",
		"policies":          "test",
		"period":            "3s",
		"ttl":               "1s",
		"num_uses":          12,
		"max_ttl":           "5s",
		"expiration_leeway": "300s",
		"not_before_leeway": "300s",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp != nil {
		t.Fatalf("Unexpected resp data: expected nil got %#v\n", resp.Data)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp != nil {
		t.Fatalf("Unexpected resp data: expected nil got %#v\n", resp.Data)
	}
}
