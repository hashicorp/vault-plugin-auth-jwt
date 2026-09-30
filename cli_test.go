// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestParseHelp(t *testing.T) {
	tests := []struct {
		name    string
		err     string
		summary string
		detail  string
	}{
		{
			err:     "",
			summary: "",
			detail:  "",
		},
		{
			err:     "No error text",
			summary: "",
			detail:  "",
		},
		{
			err:     "Errors: * This is an error.",
			summary: "Login error",
			detail:  "This is an error.",
		},
		{
			err:     "Errors: * Vault login failed. Because of reasons.",
			summary: "Vault login failed.",
			detail:  "Because of reasons.",
		},
		{
			err:     "Errors: * Token verification failed. Because of reasons.",
			summary: "Token verification failed.",
			detail:  "Because of reasons.",
		},
		{
			err:     "Errors: * No response from provider. Because of reasons.",
			summary: "No response from provider.",
			detail:  "Because of reasons.",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, d := parseError(errors.New(test.err))
			if s != test.summary {
				t.Fatalf("expected summary: %q, got: %q", test.summary, s)
			}
			if d != test.detail {
				t.Fatalf("expected detail: %q, got: %q", test.detail, d)
			}
		})
	}
}

func TestCallbackHandlerDuplicateGETUsesFirstSuccess(t *testing.T) {
	var calls atomic.Int32
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/oidc/oidc/callback" {
			http.NotFound(w, r)
			return
		}
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": "s.success",
				},
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []string{"Vault login failed. Expired or missing OAuth state."},
		})
	}))
	defer vault.Close()

	client, err := api.NewClient(&api.Config{Address: vault.URL})
	if err != nil {
		t.Fatal(err)
	}

	doneCh := make(chan loginResp, 2)
	handler := callbackHandler(client, "oidc", "nonce", doneCh)
	callback := httptest.NewServer(handler)
	defer callback.Close()

	reqURL := callback.URL + "/oidc/callback?code=auth-code&state=oauth-state"
	first, err := http.Get(reqURL)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()

	second, err := http.Get(reqURL)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Body.Close()

	for _, resp := range []*http.Response{first, second} {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "Signed in via your OIDC provider") {
			t.Fatalf("expected success HTML, got %q", body)
		}
	}

	got := <-doneCh
	if got.err != nil {
		t.Fatalf("expected first successful callback to win, got error: %v", got.err)
	}
	if got.secret == nil || got.secret.Auth == nil || got.secret.Auth.ClientToken != "s.success" {
		t.Fatalf("expected successful auth secret, got %#v", got.secret)
	}

	select {
	case extra := <-doneCh:
		t.Fatalf("duplicate callback overwrote login result: %#v err=%v", extra.secret, extra.err)
	default:
	}

	if calls.Load() != 1 {
		t.Fatalf("expected Vault callback to be invoked once, got %d", calls.Load())
	}
}
