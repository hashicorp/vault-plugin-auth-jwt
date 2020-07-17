package jwtauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

const (
	serviceAccountKeyJSON = `{"type": "service_account"}`
)

// Tests the user and group recursion logic in the search method.
func TestGSuiteProvider_search(t *testing.T) {
	groupsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m, _ := url.ParseQuery(r.URL.RawQuery)
		switch m["userKey"][0] {
		case "user1":
			w.Write([]byte(`{
				"kind": "admin#directory#groups",
				"groups": [{
					"kind": "admin#directory#group",
					"email": "group1@group.com"
				}]
			}`))
		case "group1@group.com":
			w.Write([]byte(`{
				"kind": "admin#directory#groups",
				"groups": [{
					"kind": "admin#directory#group",
					"email": "group2@group.com"
				}]
			}`))
		case "group2@group.com":
			w.Write([]byte(`{
				"kind": "admin#directory#groups",
				"groups": [{
					"kind": "admin#directory#group",
					"email": "group3@group.com"
				}]
			}`))
		case "group3@group.com":
			w.Write([]byte(`{"kind": "admin#directory#groups", "groups": []}`))
		case "noGroupUser":
			w.Write([]byte(`{"kind": "admin#directory#groups", "groups": []}`))
		}
	}))
	defer groupsServer.Close()

	type args struct {
		user   string
		config GSuiteProviderConfig
	}
	tests := []struct {
		name     string
		args     args
		expected []string
	}{
		{
			name: "fetch groups for user that's in no groups",
			args: args{
				user: "noGroupUser",
				config: GSuiteProviderConfig{
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					AdminImpersonateEmail:  "test@example.com",
					FetchGroups:            true,
				},
			},
			expected: []string{},
		},
		{
			name: "fetch groups for group that's in no groups",
			args: args{
				user: "group3@group.com",
				config: GSuiteProviderConfig{
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					AdminImpersonateEmail:  "test@example.com",
					FetchGroups:            true,
				},
			},
			expected: []string{},
		},
		{
			name: "fetch groups for user with default recursion max depth 0",
			args: args{
				user: "user1",
				config: GSuiteProviderConfig{
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					AdminImpersonateEmail:  "test@example.com",
					FetchGroups:            true,
				},
			},
			expected: []string{
				"group1@group.com",
			},
		},
		{
			name: "fetch groups for user with recursion max depth 1",
			args: args{
				user: "user1",
				config: GSuiteProviderConfig{
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					AdminImpersonateEmail:  "test@example.com",
					FetchGroups:            true,
					GroupsRecurseMaxDepth:  1,
				},
			},
			expected: []string{
				"group1@group.com",
				"group2@group.com",
			},
		},
		{
			name: "fetch groups for user with recursion max depth 10",
			args: args{
				user: "user1",
				config: GSuiteProviderConfig{
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					AdminImpersonateEmail:  "test@example.com",
					FetchGroups:            true,
					GroupsRecurseMaxDepth:  10,
				},
			},
			expected: []string{
				"group1@group.com",
				"group2@group.com",
				"group3@group.com",
			},
		},
		{
			name: "fetch groups for group with default recursion max depth 0",
			args: args{
				user: "group1@group.com",
				config: GSuiteProviderConfig{
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					AdminImpersonateEmail:  "test@example.com",
					FetchGroups:            true,
				},
			},
			expected: []string{
				"group2@group.com",
			},
		},
		{
			name: "fetch groups for group with recursion max depth 1",
			args: args{
				user: "group1@group.com",
				config: GSuiteProviderConfig{
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					AdminImpersonateEmail:  "test@example.com",
					FetchGroups:            true,
					GroupsRecurseMaxDepth:  1,
				},
			},
			expected: []string{
				"group2@group.com",
				"group3@group.com",
			},
		},
		{
			name: "fetch groups for group with recursion max depth 10",
			args: args{
				user: "group1@group.com",
				config: GSuiteProviderConfig{
					serviceAccountKeyJSON:  []byte(serviceAccountKeyJSON),
					ServiceAccountFilePath: "/path/to/google-service-account.json",
					AdminImpersonateEmail:  "test@example.com",
					FetchGroups:            true,
					GroupsRecurseMaxDepth:  10,
				},
			},
			expected: []string{
				"group2@group.com",
				"group3@group.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize the provider
			gProvider := new(GSuiteProvider)
			assert.NoError(t, gProvider.initialize(tt.args.config))

			// Fetch groups from the groupsServer
			ctx := context.Background()
			gProvider.adminSvc, _ = admin.NewService(ctx, option.WithHTTPClient(&http.Client{}))
			gProvider.adminSvc.BasePath = groupsServer.URL
			groups := make(map[string]bool)
			assert.NoError(t, gProvider.search(ctx, groups, tt.args.user, gProvider.config.GroupsRecurseMaxDepth))

			// Assert that we got the expected groups
			assert.Equal(t, len(tt.expected), len(groups))
			for _, group := range tt.expected {
				_, ok := groups[group]
				assert.True(t, ok)
			}
		})
	}
}

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
