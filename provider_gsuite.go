package jwtauth

import (
	"context"

	"golang.org/x/oauth2/jwt"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

// fetchGoogleGroups queries the google api to fetch a given user's group memberships
func (b *jwtAuthBackend) fetchGoogleGroups(ctx context.Context, config *jwt.Config, subject string) ([]interface{}, error) {
	var userGroups []interface{}
	var nextPageToken string

	adminService, err := admin.NewService(ctx, option.WithHTTPClient(config.Client(ctx)))
	if err != nil {
		return nil, err
	}

	for {
		groupsResponse, err := adminService.Groups.List().Context(ctx).PageToken(nextPageToken).UserKey(subject).Do()
		if err != nil {
			return nil, err
		}

		for _, group := range groupsResponse.Groups {
			userGroups = append(userGroups, group.Email)
		}

		if groupsResponse.NextPageToken == "" {
			break
		}

		nextPageToken = groupsResponse.NextPageToken
	}

	return userGroups, nil
}
