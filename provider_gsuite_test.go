package jwtauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	serviceAccountKeyJSON = `{"type": "service_account"}`
)

func TestGSuiteProvider_initialize(t *testing.T) {
	type args struct {
		config GSuiteProviderConfig
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "invalid config: required service account key is empty",
			args: args{
				config: GSuiteProviderConfig{
					AdminImpersonateEmail: "test@example.com",
					GroupsRecurseMaxDepth: -1,
					UserCustomSchemas:     "Custom",
					serviceAccountKeyJSON: []byte(serviceAccountKeyJSON),
				},
			},
			wantErr: true,
		},
		{
			name: "invalid config: required admin impersonate email is empty",
			args: args{
				config: GSuiteProviderConfig{
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					GroupsRecurseMaxDepth:  -1,
					UserCustomSchemas:      "Custom",
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
				},
			},
			wantErr: true,
		},
		{
			name: "invalid config: recurse max depth negative number",
			args: args{
				config: GSuiteProviderConfig{
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					AdminImpersonateEmail:  "test@example.com",
					GroupsRecurseMaxDepth:  -1,
					UserCustomSchemas:      "Custom",
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
				},
			},
			wantErr: true,
		},
		{
			name: "valid config: all options",
			args: args{
				config: GSuiteProviderConfig{
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					AdminImpersonateEmail:  "test@example.com",
					GroupsRecurseMaxDepth:  5,
					UserCustomSchemas:      "Custom",
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
				},
			},
			wantErr: false,
		},
		{
			name: "valid config: no custom schemas",
			args: args{
				config: GSuiteProviderConfig{
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					AdminImpersonateEmail:  "test@example.com",
					GroupsRecurseMaxDepth:  5,
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
				},
			},
			wantErr: false,
		},
		{
			name: "valid config: no recurse max depth",
			args: args{
				config: GSuiteProviderConfig{
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					AdminImpersonateEmail:  "test@example.com",
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
					UserCustomSchemas:      "Custom",
				},
			},
			wantErr: false,
		},
		{
			name: "valid config: fetch groups and user info",
			args: args{
				config: GSuiteProviderConfig{
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					AdminImpersonateEmail:  "test@example.com",
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
					UserCustomSchemas:      "Custom",
					FetchGroups:            true,
					FetchUserInfo:          true,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &GSuiteProvider{}
			if tt.wantErr {
				assert.Error(t, g.initialize(tt.args.config))
			} else {
				assert.NoError(t, g.initialize(tt.args.config))
			}
		})
	}
}
