package jwtauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2"
)

const (
	// defaultOktaGroupsCap is Okta's default ID-token groups-claim
	// truncation threshold. When a user belongs to more groups than
	// this, Okta drops groups silently rather than aggregating
	// distributed claims. Configurable per Okta authorization server;
	// override via provider_config.groups_cap.
	defaultOktaGroupsCap = 100

	// oktaUserGroupsPathFmt is the Okta admin API path that returns
	// the groups a user belongs to. The {user} segment accepts an
	// Okta user id, login (email/UPN), or unique login shortname.
	oktaUserGroupsPathFmt = "/api/v1/users/%s/groups"
)

// OktaProvider returns the full set of Okta groups a user belongs to
// when Okta has truncated the id-token's groups claim. It calls Okta's
// admin endpoint
//
//	GET /api/v1/users/{user}/groups
//
// authenticated with a configured Okta API token (SSWS), following
// RFC 5988 Link-header pagination.
//
// This endpoint is admin-only and cannot be reached with an end-user
// OAuth token regardless of okta.* scopes. The provider therefore
// requires an Okta API token bound to a user with permission to read
// users and read groups (a least-privilege custom admin role granting
// "View users and their details" and "View groups and their details"
// is sufficient). The token is supplied via provider_config.api_token
// and is masked from config reads.
type OktaProvider struct {
	ctx    context.Context
	config OktaProviderConfig

	// groupsFilter is the compiled form of OktaProviderConfig.GroupsFilter.
	// Nil when no filter is configured.
	groupsFilter *regexp.Regexp
}

// OktaProviderConfig is decoded from jwtConfig.ProviderConfig during
// Initialize.
type OktaProviderConfig struct {
	// OrgURL is the Okta org base URL, e.g. https://example.okta.com.
	// Must use https.
	OrgURL string `mapstructure:"org_url"`

	// APIToken is an Okta API token (SSWS) used to authenticate the
	// server-side groups lookup. Required.
	APIToken string `mapstructure:"api_token"`

	// UserIDClaim names the claim in the OIDC token whose value
	// identifies the user to Okta. The value must be one of: the
	// user's Okta id, login (email/UPN), or unique login shortname.
	// Optional; when empty, the role's user_claim is used.
	UserIDClaim string `mapstructure:"user_id_claim"`

	// GroupsCap is the Okta id-token groups truncation threshold. When
	// the groups claim is present with length >= GroupsCap, the
	// provider treats it as truncated and re-fetches the full list
	// via the admin API. Defaults to 100.
	GroupsCap int `mapstructure:"groups_cap"`

	// GroupsFilter is an optional Go regular expression. When
	// non-empty, only groups whose name matches the pattern are
	// returned to Vault. Applied identically to both the id-token
	// claim path and the API fallback path so behavior is consistent
	// regardless of whether the user crossed GroupsCap. Empty (the
	// default) disables filtering; every group Okta returns passes
	// through.
	GroupsFilter string `mapstructure:"groups_filter"`
}

// Initialize validates and stores provider configuration. Satisfies
// the CustomProvider interface.
func (o *OktaProvider) Initialize(_ context.Context, jc *jwtConfig) error {
	var cfg OktaProviderConfig
	if err := mapstructure.Decode(jc.ProviderConfig, &cfg); err != nil {
		return err
	}
	if cfg.OrgURL == "" {
		return errors.New("'org_url' must be set in provider_config for the okta provider")
	}
	u, err := url.Parse(cfg.OrgURL)
	if err != nil {
		return fmt.Errorf("invalid org_url: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("org_url must use https")
	}
	if cfg.APIToken == "" {
		return errors.New("'api_token' must be set in provider_config for the okta provider")
	}
	if cfg.GroupsCap < 0 {
		return errors.New("groups_cap must be >= 0")
	}
	if cfg.GroupsCap == 0 {
		cfg.GroupsCap = defaultOktaGroupsCap
	}
	if cfg.GroupsFilter != "" {
		re, err := regexp.Compile(cfg.GroupsFilter)
		if err != nil {
			return fmt.Errorf("invalid groups_filter regex: %w", err)
		}
		o.groupsFilter = re
	}
	o.config = cfg
	return nil
}

// SensitiveKeys returns fields that must be masked when reading the
// provider config back. Satisfies the CustomProvider interface.
func (o *OktaProvider) SensitiveKeys() []string {
	return []string{"api_token"}
}

// FetchGroups implements GroupsFetcher. Returns the id-token groups
// claim when it's clearly untruncated; otherwise calls the Okta
// admin API using the configured SSWS token. When groups_filter is
// set, both paths return only the subset of group names matching the
// configured regex.
func (o *OktaProvider) FetchGroups(_ context.Context, b *jwtAuthBackend, allClaims map[string]interface{}, role *jwtRole, _ oauth2.TokenSource) (interface{}, error) {
	groupsClaimRaw := getClaim(b.Logger(), allClaims, role.GroupsClaim)

	if groupsClaimRaw != nil {
		if list, ok := normalizeList(groupsClaimRaw); ok && len(list) < o.config.GroupsCap {
			if o.groupsFilter == nil {
				return groupsClaimRaw, nil
			}
			return o.applyGroupsFilter(b, list), nil
		}
	}

	userID, err := o.resolveUserID(b, allClaims, role)
	if err != nil {
		return nil, err
	}

	o.ctx, err = b.createCAContext(b.providerCtx, b.cachedConfig.OIDCDiscoveryCAPEM)
	if err != nil {
		return nil, fmt.Errorf("unable to create CA context: %w", err)
	}

	groups, err := o.getOktaGroups(userID)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch groups from Okta API: %w", err)
	}
	b.Logger().Debug("groups fetched from Okta API", "count", len(groups))
	if o.groupsFilter != nil {
		groups = o.applyGroupsFilter(b, groups)
	}
	return groups, nil
}

// resolveUserID returns the value of the configured user_id_claim, or
// the role's user_claim if user_id_claim is unset. Must be a string
// that Okta accepts as a user identifier.
func (o *OktaProvider) resolveUserID(b *jwtAuthBackend, allClaims map[string]interface{}, role *jwtRole) (string, error) {
	claim := o.config.UserIDClaim
	if claim == "" {
		claim = role.UserClaim
	}
	if claim == "" {
		return "", errors.New("user_id_claim is unset and role has no user_claim")
	}
	raw := getClaim(b.Logger(), allClaims, claim)
	if raw == nil {
		return "", fmt.Errorf("unable to locate %q in claims for Okta user lookup", claim)
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("claim %q is not a string; cannot use for Okta user lookup", claim)
	}
	if s == "" {
		return "", fmt.Errorf("claim %q is empty; cannot use for Okta user lookup", claim)
	}
	return s, nil
}

// applyGroupsFilter returns the subset of list whose elements are
// strings matching o.groupsFilter. Non-string entries are dropped.
// Caller must only invoke this when groupsFilter is non-nil.
func (o *OktaProvider) applyGroupsFilter(b *jwtAuthBackend, list []interface{}) []interface{} {
	out := make([]interface{}, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			continue
		}
		if o.groupsFilter.MatchString(s) {
			out = append(out, s)
		}
	}
	b.Logger().Debug("groups filter applied", "before", len(list), "after", len(out))
	return out
}

// getOktaGroups fetches every group the named user belongs to from
// /api/v1/users/{userID}/groups, following RFC 5988 Link-header
// pagination. Authenticated with the configured admin API token.
func (o *OktaProvider) getOktaGroups(userID string) ([]interface{}, error) {
	client := http.DefaultClient
	if c, ok := o.ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}

	next := strings.TrimRight(o.config.OrgURL, "/") + fmt.Sprintf(oktaUserGroupsPathFmt, url.PathEscape(userID))

	var all []interface{}
	for next != "" {
		req, err := http.NewRequest("GET", next, nil)
		if err != nil {
			return nil, fmt.Errorf("error constructing groups request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "SSWS "+o.config.APIToken)

		res, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("unable to call Okta API: %w", err)
		}
		body, readErr := io.ReadAll(res.Body)
		res.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("failed to read Okta API response: %w", readErr)
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("okta api returned %d: %s", res.StatusCode, string(body))
		}

		var page []oktaGroup
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("unable to decode Okta API response: %w", err)
		}
		for _, g := range page {
			if g.Profile.Name != "" {
				all = append(all, g.Profile.Name)
			}
		}
		next = nextLink(res.Header.Values("Link"))
	}

	return all, nil
}

// oktaGroup is a partial shape of Okta's Group resource.
type oktaGroup struct {
	ID      string           `json:"id"`
	Profile oktaGroupProfile `json:"profile"`
}

type oktaGroupProfile struct {
	Name string `json:"name"`
}

// linkNextRE matches the URL in a Link header entry whose rel="next",
// per RFC 5988, e.g. <https://example.okta.com/...>; rel="next".
var linkNextRE = regexp.MustCompile(`<([^>]+)>\s*;\s*rel\s*=\s*"next"`)

// nextLink returns the URL of the rel="next" link from a slice of
// Link header values, or "" if none is present.
func nextLink(headers []string) string {
	for _, h := range headers {
		if m := linkNextRE.FindStringSubmatch(h); m != nil {
			return m[1]
		}
	}
	return ""
}
