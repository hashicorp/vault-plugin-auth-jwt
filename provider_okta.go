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
	// truncation cap. When a user belongs to more groups than this,
	// Okta drops groups silently rather than aggregating distributed
	// claims. The cap is configurable per Okta auth server; override
	// via provider_config.groups_cap.
	defaultOktaGroupsCap = 100

	// oktaUserGroupsPath is the Okta API path that returns the
	// calling user's groups. "me" resolves from the access token, so
	// no admin scope is needed beyond okta.groups.read (or the
	// equivalent self-scoped read).
	oktaUserGroupsPath = "/api/v1/users/me/groups"
)

// OktaProvider handles group resolution for OIDC logins against Okta
// when the user's ID-token groups claim has been truncated. It uses
// the user's own OAuth access token to call the Okta groups API and
// returns the full paginated list, mirroring the role played by
// AzureProvider for Entra ID's distributed _claim_sources pattern.
//
// There is no static admin credential; the provider works only when
// the OIDC role surfaces the access token (role option:
// oauth2_metadata = ["access_token"]) and the Okta authorization
// server has been configured to issue access tokens carrying
// okta.groups.read (or okta.users.read.self + okta.groups.read).
type OktaProvider struct {
	ctx    context.Context
	config OktaProviderConfig
}

// OktaProviderConfig is decoded from jwtConfig.ProviderConfig during
// Initialize.
type OktaProviderConfig struct {
	// OrgURL is the Okta org base URL, e.g. https://example.okta.com.
	// Must use https.
	OrgURL string `mapstructure:"org_url"`
	// GroupsCap is the Okta ID-token groups truncation threshold. When
	// the groups claim is present with length >= GroupsCap, we assume
	// it has been truncated and re-fetch via the API. Defaults to 100.
	GroupsCap int `mapstructure:"groups_cap"`
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
	if cfg.GroupsCap < 0 {
		return errors.New("groups_cap must be >= 0")
	}
	if cfg.GroupsCap == 0 {
		cfg.GroupsCap = defaultOktaGroupsCap
	}
	o.config = cfg
	return nil
}

// SensitiveKeys returns fields that should be masked in config output.
// The Okta provider stores no secret material, so the list is empty.
// Satisfies the CustomProvider interface.
func (o *OktaProvider) SensitiveKeys() []string {
	return []string{}
}

// FetchGroups implements GroupsFetcher. It returns the groups claim
// from the ID token when it's clearly untruncated; otherwise it falls
// back to the Okta groups API using the user's access token.
func (o *OktaProvider) FetchGroups(_ context.Context, b *jwtAuthBackend, allClaims map[string]interface{}, role *jwtRole, tokenSource oauth2.TokenSource) (interface{}, error) {
	groupsClaimRaw := getClaim(b.Logger(), allClaims, role.GroupsClaim)

	if groupsClaimRaw != nil {
		if list, ok := normalizeList(groupsClaimRaw); ok && len(list) < o.config.GroupsCap {
			return groupsClaimRaw, nil
		}
	}

	var err error
	o.ctx, err = b.createCAContext(b.providerCtx, b.cachedConfig.OIDCDiscoveryCAPEM)
	if err != nil {
		return nil, fmt.Errorf("unable to create CA context: %w", err)
	}

	groups, err := o.getOktaGroups(tokenSource)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch groups from Okta API: %w", err)
	}
	b.Logger().Debug("groups fetched from Okta API", "count", len(groups))
	return groups, nil
}

// getOktaGroups fetches every group the caller belongs to from
// /api/v1/users/me/groups, following Okta's RFC 5988 Link-header
// pagination. The caller is identified implicitly by the access token.
func (o *OktaProvider) getOktaGroups(tokenSource oauth2.TokenSource) ([]interface{}, error) {
	if tokenSource == nil {
		return nil, errors.New("token source unavailable; cannot call Okta API")
	}
	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("unable to get token: %w", err)
	}
	if token.AccessToken == "" {
		return nil, errors.New("access token is empty; cannot call Okta API")
	}

	client := http.DefaultClient
	if c, ok := o.ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}

	next := strings.TrimRight(o.config.OrgURL, "/") + oktaUserGroupsPath

	var all []interface{}
	for next != "" {
		req, err := http.NewRequest("GET", next, nil)
		if err != nil {
			return nil, fmt.Errorf("error constructing groups request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		token.SetAuthHeader(req)

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
	ID      string          `json:"id"`
	Profile oktaGroupProfile `json:"profile"`
}

type oktaGroupProfile struct {
	Name string `json:"name"`
}

// linkNextRE matches the URL in a Link header entry whose rel="next",
// per RFC 5988, e.g. <https://example.okta.com/...>; rel="next".
var linkNextRE = regexp.MustCompile(`<([^>]+)>\s*;\s*rel\s*=\s*"next"`)

// nextLink returns the URL of the rel="next" link from a slice of Link
// header values, or "" if none is present.
func nextLink(headers []string) string {
	for _, h := range headers {
		if m := linkNextRE.FindStringSubmatch(h); m != nil {
			return m[1]
		}
	}
	return ""
}
