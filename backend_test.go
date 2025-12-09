// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"testing"

	"github.com/hashicorp/cap/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_jwtAuthBackend_jwtValidator(t *testing.T) {
	type args struct {
		config *jwtConfig
	}
	tests := []struct {
		name        string
		args        args
		want        *jwt.Validator
		expectedErr string
	}{
		{
			name: "invalid ca pem",
			args: args{
				config: &jwtConfig{
					JWKSPairs: []interface{}{
						map[string]any{
							"jwks_url":    "https://www.foobar.com/something",
							"jwks_ca_pem": "defg",
						},
						map[string]any{
							"jwks_url":    "https://www.barbaz.com/something",
							"jwks_ca_pem": "",
						},
					},
				},
			},
			expectedErr: "could not parse CA PEM value successfully",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &jwtAuthBackend{}
			b.providerCtx = context.TODO()

			got, err := b.jwtValidator(tt.args.config)
			if tt.expectedErr != "" {
				require.ErrorContains(t, err, tt.expectedErr)
				return
			}
			assert.Equalf(t, tt.want, got, "jwtValidator(%v)", tt.args.config)
		})
	}
}
