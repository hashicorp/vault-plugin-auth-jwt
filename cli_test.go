// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
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

// TestCLIHandler_Help verifies that Help uses BinaryName in the commands it
// shows and falls back to "vault" when it's unset.
func TestCLIHandler_Help(t *testing.T) {
	t.Parallel()

	require.Contains(t, (&CLIHandler{}).Help(), "vault login -method=oidc")

	help := (&CLIHandler{BinaryName: "vault-client"}).Help()
	require.Contains(t, help, "vault-client login -method=oidc")
	require.NotContains(t, help, "vault login")

	// Make sure a binary name with a format verb shows up as is
	require.Contains(t, (&CLIHandler{BinaryName: "client-%s"}).Help(), "client-%s login -method=oidc")
}
