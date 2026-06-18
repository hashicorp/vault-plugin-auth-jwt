// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAzureWorkloadIdentityAssertion_Serialize(t *testing.T) {
	t.Run("reads and trims the federated token file", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := filepath.Join(dir, "token")
		require.NoError(t, os.WriteFile(tokenFile, []byte("  federated.jwt.token\n"), 0o600))
		t.Setenv(azureFederatedTokenFileEnv, tokenFile)

		got, err := azureWorkloadIdentityAssertion{}.Serialize()
		require.NoError(t, err)
		require.Equal(t, "federated.jwt.token", got)
	})

	t.Run("errors when the env var is unset", func(t *testing.T) {
		t.Setenv(azureFederatedTokenFileEnv, "")
		_, err := azureWorkloadIdentityAssertion{}.Serialize()
		require.Error(t, err)
	})

	t.Run("errors when the file is missing", func(t *testing.T) {
		t.Setenv(azureFederatedTokenFileEnv, filepath.Join(t.TempDir(), "does-not-exist"))
		_, err := azureWorkloadIdentityAssertion{}.Serialize()
		require.Error(t, err)
	})
}

func TestAzureWorkloadIdentityEnabled(t *testing.T) {
	tests := []struct {
		name           string
		providerConfig map[string]interface{}
		want           bool
	}{
		{
			name:           "nil provider config",
			providerConfig: nil,
			want:           false,
		},
		{
			name:           "azure provider without flag",
			providerConfig: map[string]interface{}{"provider": "azure"},
			want:           false,
		},
		{
			name:           "azure provider with flag enabled",
			providerConfig: map[string]interface{}{"provider": "azure", "use_workload_identity": true},
			want:           true,
		},
		{
			name:           "azure provider with flag disabled",
			providerConfig: map[string]interface{}{"provider": "azure", "use_workload_identity": false},
			want:           false,
		},
		{
			name:           "non-azure provider with flag enabled",
			providerConfig: map[string]interface{}{"provider": "gsuite", "use_workload_identity": true},
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := jwtConfig{ProviderConfig: tt.providerConfig}
			require.Equal(t, tt.want, c.azureWorkloadIdentityEnabled())
		})
	}
}

func TestAzureWorkloadIdentity_AuthTypeIsOIDCFlow(t *testing.T) {
	// With a client ID and discovery URL but no client secret, the config would
	// normally be classified as OIDCDiscovery. Enabling Azure workload identity
	// must promote it to the full OIDCFlow so the login/callback paths run.
	c := jwtConfig{
		OIDCDiscoveryURL: "https://login.microsoftonline.com/tenant/v2.0",
		OIDCClientID:     "client-id",
		ProviderConfig:   map[string]interface{}{"provider": "azure", "use_workload_identity": true},
	}
	require.Equal(t, OIDCFlow, c.authType())

	// Without the flag (and no secret) it remains plain discovery.
	c.ProviderConfig = map[string]interface{}{"provider": "azure"}
	require.Equal(t, OIDCDiscovery, c.authType())
}
