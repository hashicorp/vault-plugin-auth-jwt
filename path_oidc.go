package jwtauth

import (
	"context"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/base62"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/oauth2"
)

// base62 char length for state and nonce parameters, ~160 bits entropy per rfc6749#section-10.10
const stateLength = 27

var oidcStateTimeout = 2 * time.Minute

// oidcState is created when an authURL is requested. The state identifier is
// passed throughout the OAuth process.
type oidcState struct {
	rolename    string
	expiration  time.Time
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
//
// TODO: I think we should probably just log all errors and return nil instead of
//       the usual "return nil, err" pattern. We can still return a user error when
//       they've not provided a required field though.
func (b *jwtAuthBackend) authURL(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	authCodeURL := ""

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}

	roleName := d.Get("role").(string)
	if roleName == "" {
		roleName = config.DefaultRole
		if roleName == "" {
			return logical.ErrorResponse("missing role"), nil
		}
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	redirectURI := d.Get("redirect_uri").(string)
	if redirectURI == "" {
		return logical.ErrorResponse("missing redirect_uri"), nil
	}

	if role != nil && role.RoleType == "oidc" {
		provider, err := b.getProvider(ctx, config)
		if err != nil {
			return nil, errwrap.Wrapf("error getting provider for login operation: {{err}}", err)
		}

		if len(role.AllowedRedirectURIs) == 0 ||
			strutil.StrListContains(role.AllowedRedirectURIs, redirectURI) {

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
				return nil, errwrap.Wrapf("error generating OAuth state: {{err}}", err)
			}

			authCodeURL = oauth2Config.AuthCodeURL(stateID, oidc.Nonce(nonce))
		}
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"auth_url": authCodeURL,
		},
	}

	return resp, nil
}

// createState make an expiring state object, associated with a random state ID
// that is passed throughout the OAuth process. A nonce is also included in the
// auth process, and for simplicity will be identical in length/format as the state ID.
func (b *jwtAuthBackend) createState(rolename, redirectURI string) (string, string, error) {
	randstr, err := base62.Random(2 * stateLength)
	if err != nil {
		return "", "", err
	}

	stateID, nonce := randstr[0:stateLength], randstr[stateLength:]

	b.l.Lock()
	b.oidcStates[stateID] = &oidcState{
		rolename:    rolename,
		expiration:  time.Now().Add(oidcStateTimeout),
		nonce:       nonce,
		redirectURI: redirectURI,
	}
	b.l.Unlock()

	return stateID, nonce, nil
}

// verifyState tests whether the provided state ID is valid and returns the
// associated state object if so. A nil state is returned if the ID is not found
// or expired. The state should only ever be retrieved once and is deleted as
// part of this request.
func (b *jwtAuthBackend) verifyState(state string) *oidcState {
	b.l.Lock()
	defer b.l.Unlock()

	s := b.oidcStates[state]
	if s != nil && time.Now().After(s.expiration) {
		s = nil
	}

	delete(b.oidcStates, state)

	return s
}

// stateGC will start a goroutine which periodically deletes all expired states
// that were never removed via the normal request process.
func (b *jwtAuthBackend) stateGC() {
	go func() {
		for {
			now := time.Now()
			b.l.Lock()
			for k := range b.oidcStates {
				if now.After(b.oidcStates[k].expiration) {
					delete(b.oidcStates, k)
				}
			}
			b.l.Unlock()
			time.Sleep(1 * time.Minute)
		}
	}()
}
