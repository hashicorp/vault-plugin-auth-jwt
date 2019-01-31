package jwtauth

import (
	"context"
	"fmt"
	"time"

	oidc "github.com/coreos/go-oidc"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/oauth2"
)

var oidcStateTimeout = 10 * time.Minute

// oidcState is created when an authURL is requested. The state identifier is
// passed throughout the OAuth process.
type oidcState struct {
	rolename    string
	nonce       string
	redirectURI string
}

func pathOIDC(b *jwtAuthBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `oidc/auth_url`,
			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:        framework.TypeLowerCaseString,
					Description: "The role to issue an OIDC authorization URL against.",
				},
				"redirect_uri": {
					Type:        framework.TypeString,
					Description: "The OAuth redirect_uri to use in the authorization URL.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.authURL,
			},
		},
	}
}

// authURL returns a URL used for redirection to receive an authorization code.
// This path requires a role name, or that a default_role has been configured.
// Because this endpoint is unauthenticated, the response to invalid or non-OIDC
// roles is intentionally non-descriptive and will simply be an empty string.
func (b *jwtAuthBackend) authURL(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	logger := b.Logger()

	// default response for most error/invalid conditions
	resp := &logical.Response{
		Data: map[string]interface{}{
			"auth_url": "",
		},
	}

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		logger.Warn("error loading configuration", "error", err)
		return resp, nil
	}

	if config == nil {
		logger.Warn("nil configuration")
		return resp, nil
	}

	roleName := d.Get("role").(string)
	if roleName == "" {
		roleName = config.DefaultRole
		if roleName == "" {
			return logical.ErrorResponse("missing role"), nil
		}
	}

	redirectURI := d.Get("redirect_uri").(string)
	if redirectURI == "" {
		return logical.ErrorResponse("missing redirect_uri"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		logger.Warn("error loading role", "error", err)
		return resp, nil
	}

	if role == nil || role.RoleType != "oidc" {
		logger.Warn("invalid role type", "role type", role)
		return resp, nil
	}

	if !strutil.StrListContains(role.AllowedRedirectURIs, redirectURI) {
		logger.Warn("unauthorized redirect_uri", "redirect_uri", redirectURI)
		return resp, nil
	}

	provider, err := b.getProvider(ctx, config)
	if err != nil {
		logger.Warn("error getting provider for login operation", "error", err)
		return resp, nil
	}

	// "openid" is a required scope for OpenID Connect flows
	scopes := append([]string{oidc.ScopeOpenID}, role.OIDCScopes...)

	// Configure an OpenID Connect aware OAuth2 client
	oauth2Config := oauth2.Config{
		ClientID:     config.OIDCClientID,
		ClientSecret: config.OIDCClientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	stateID, nonce, err := b.createState(roleName, redirectURI)
	if err != nil {
		logger.Warn("error generating OAuth state", "error", err)
		return resp, nil
	}

	resp.Data["auth_url"] = oauth2Config.AuthCodeURL(stateID, oidc.Nonce(nonce))

	return resp, nil
}

// createState make an expiring state object, associated with a random state ID
// that is passed throughout the OAuth process. A nonce is also included in the
// auth process, and for simplicity will be identical in length/format as the state ID.
func (b *jwtAuthBackend) createState(rolename, redirectURI string) (string, string, error) {
	// Get enough bytes for 2 160-bit IDs (per rfc6749#section-10.10)
	bytes, err := uuid.GenerateRandomBytes(2 * 20)
	if err != nil {
		return "", "", err
	}

	stateID := fmt.Sprintf("%x", bytes[:20])
	nonce := fmt.Sprintf("%x", bytes[20:])

	b.oidcStates.SetDefault(stateID, &oidcState{
		rolename:    rolename,
		nonce:       nonce,
		redirectURI: redirectURI,
	})

	return stateID, nonce, nil
}

// verifyState tests whether the provided state ID is valid and returns the
// associated state object if so. A nil state is returned if the ID is not found
// or expired. The state should only ever be retrieved once and is deleted as
// part of this request.
func (b *jwtAuthBackend) verifyState(stateID string) *oidcState {
	defer b.oidcStates.Delete(stateID)

	if stateRaw, ok := b.oidcStates.Get(stateID); ok {
		return stateRaw.(*oidcState)
	}

	return nil
}
