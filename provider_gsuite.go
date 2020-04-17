package jwtauth

import (
	"context"
	"encoding/json"

	"golang.org/x/oauth2/jwt"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

func (b *jwtAuthBackend) fillGoogleCustomSchemas(ctx context.Context, adminService *admin.Service, allClaims map[string]interface{}, subject, customSchemas string) error {
	userResponse, err := adminService.Users.Get(subject).Context(ctx).Projection("custom").CustomFieldMask(customSchemas).Fields("customSchemas").Do()
	if err != nil {
		return err
	}

	for schema, rawValue := range userResponse.CustomSchemas {
		// note: metadata extraction only supports strings as values, but filtering
		// happens later so we must use interface{}
		var value map[string]interface{}
		if err := json.Unmarshal(rawValue, &value); err != nil {
			return err
		}

		allClaims[schema] = value
	}

	return nil
}

func (b *jwtAuthBackend) fillGoogleGroups(ctx context.Context, adminService *admin.Service, allClaims map[string]interface{}, subject string, recurseMaxDepth int) error {
	var userGroupsMap = make(map[string]struct{})
	var search func(subject string, depth int) error

	search = func(subject string, depth int) error {
		var newGroups []string
		if err := adminService.Groups.List().UserKey(subject).Fields("nextPageToken", "groups(email)").Pages(ctx, func(groups *admin.Groups) error {
			for _, group := range groups.Groups {
				if _, ok := userGroupsMap[group.Email]; ok {
					continue
				}
				userGroupsMap[group.Email] = struct{}{}
				newGroups = append(newGroups, group.Email)
			}
			return nil
		}); err != nil {
			return err
		}
		if depth <= 0 {
			return nil
		}

		for _, email := range newGroups {
			// note: go sdk does not implement batching
			if err := search(email, depth-1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := search(subject, recurseMaxDepth); err != nil {
		return err
	}

	var userGroups = make([]interface{}, 0, len(userGroupsMap))
	for email := range userGroupsMap {
		userGroups = append(userGroups, email)
	}
	allClaims["groups"] = userGroups
	return nil
}

// fillGoogleInfo is the equivalent of the OIDC /userinfo endpoint for GSuite
func (b *jwtAuthBackend) fillGoogleInfo(ctx context.Context, config *jwt.Config, subject string, customSchemas string, allClaims map[string]interface{}, recurseMaxDepth int) error {
	adminService, err := admin.NewService(ctx, option.WithHTTPClient(config.Client(ctx)))
	if err != nil {
		return err
	}

	if customSchemas != "" {
		if err := b.fillGoogleCustomSchemas(ctx, adminService, allClaims, subject, customSchemas); err != nil {
			return err
		}
	}

	if err := b.fillGoogleGroups(ctx, adminService, allClaims, subject, recurseMaxDepth); err != nil {
		return err
	}

	return nil
}
