package jwtauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/cidrutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"gopkg.in/square/go-jose.v2/jwt"
)

func pathLogin(b *jwtAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `login$`,
		Fields: map[string]*framework.FieldSchema{
			"role": &framework.FieldSchema{
				Type:        framework.TypeLowerCaseString,
				Description: "The role to log in against.",
			},
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The signed JWT to validate.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathLogin,
		},

		HelpSynopsis:    pathLoginHelpSyn,
		HelpDescription: pathLoginHelpDesc,
	}
}

func (b *jwtAuthBackend) pathLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	token := d.Get("token").(string)
	if len(token) == 0 {
		return logical.ErrorResponse("missing token"), nil
	}

	roleName := d.Get("role").(string)
	if len(roleName) == 0 {
		return logical.ErrorResponse("missing role"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role could not be found"), nil
	}

	if req.Connection != nil && !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.BoundCIDRs) {
		return logical.ErrorResponse("request originated from invalid CIDR"), nil
	}

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}

	// Here is where things diverge. If it is using OIDC discovery, validate
	// that way; otherwise validate against the locally configured keys. Once
	// things are validated, we re-unify the request path when evaluating the
	// claims.
	allClaims := map[string]interface{}{}
	switch {
	case len(config.ParsedJWTPubKeys) != 0:
		parsedJWT, err := jwt.ParseSigned(token)
		if err != nil {
			return logical.ErrorResponse(errwrap.Wrapf("error parsing token: {{err}}", err).Error()), nil
		}

		claims := jwt.Claims{}

		var valid bool
		for _, key := range config.ParsedJWTPubKeys {
			if err := parsedJWT.Claims(key, &claims, allClaims); err == nil {
				valid = true
				break
			}
		}
		if !valid {
			return logical.ErrorResponse("no known key successfully validated the token signature"), nil
		}

		expected := jwt.Expected{
			Issuer:   config.BoundIssuer,
			Subject:  role.BoundSubject,
			Audience: jwt.Audience(role.BoundAudiences),
			Time:     time.Now(),
		}

		if err := claims.Validate(expected); err != nil {
			return logical.ErrorResponse(errwrap.Wrapf("error validating claims: {{err}}", err).Error()), nil
		}

	case config.OIDCIssuerURL != "":
		provider, err := b.getProvider(ctx, config)
		if err != nil {
			return nil, errwrap.Wrapf("error getting provider for login operation: {{err}}", err)
		}

		verifier := provider.Verifier(&oidc.Config{
			SkipClientIDCheck: true,
		})

		idToken, err := verifier.Verify(ctx, token)
		if err != nil {
			return logical.ErrorResponse(errwrap.Wrapf("error validating signature: {{err}}", err).Error()), nil
		}

		if err := idToken.Claims(allClaims); err != nil {
			return logical.ErrorResponse(errwrap.Wrapf("unable to successfully parse all claims from token: {{err}}", err).Error()), nil
		}

		switch {
		case role.BoundSubject != "" && role.BoundSubject != idToken.Subject:
			return logical.ErrorResponse("sub claim does not match bound subject"), nil
		case len(role.BoundAudiences) != 0 && !strutil.StrListSubset(role.BoundAudiences, idToken.Audience):
			return logical.ErrorResponse("aud claim does not match any bound audience"), nil
		}

	default:
		return nil, errors.New("unhandled case during login")
	}

	userClaimRaw, ok := allClaims[role.UserClaim]
	if !ok {
		return logical.ErrorResponse(fmt.Sprintf("%q claim not found in token", role.UserClaim)), nil
	}
	userName, ok := userClaimRaw.(string)
	if !ok {
		return logical.ErrorResponse(fmt.Sprintf("%q claim could not be converted to string", role.UserClaim)), nil
	}

	var groupAliases []*logical.Alias
	if role.GroupsClaim != "" {
		groupsClaimRaw, ok := allClaims[role.GroupsClaim]
		if !ok {
			return logical.ErrorResponse(fmt.Sprintf("%q claim not found in token", role.GroupsClaim)), nil
		}
		groups, ok := groupsClaimRaw.([]interface{})
		if !ok {
			return logical.ErrorResponse(fmt.Sprintf("%q claim could not be converted to string list", role.GroupsClaim)), nil
		}
		for _, groupRaw := range groups {
			group, ok := groupRaw.(string)
			if !ok {
				return logical.ErrorResponse(fmt.Sprintf("value %v in groups claim could not be parsed as string", groupRaw)), nil
			}
			if group == "" {
				continue
			}
			groupAliases = append(groupAliases, &logical.Alias{
				Name: group,
			})
		}
	}

	resp := &logical.Response{
		Auth: &logical.Auth{
			Policies:    role.Policies,
			DisplayName: userName,
			Period:      role.Period,
			NumUses:     role.NumUses,
			Alias: &logical.Alias{
				Name: userName,
			},
			GroupAliases: groupAliases,
			InternalData: map[string]interface{}{
				"role": roleName,
			},
			Metadata: map[string]string{
				"role": roleName,
			},
			LeaseOptions: logical.LeaseOptions{
				Renewable: true,
				TTL:       role.TTL,
				MaxTTL:    role.MaxTTL,
			},
			BoundCIDRs: role.BoundCIDRs,
		},
	}

	return resp, nil
}

func (b *jwtAuthBackend) pathLoginRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := req.Auth.InternalData["role"].(string)
	if roleName == "" {
		return nil, errors.New("failed to fetch role_name during renewal")
	}

	// Ensure that the Role still exists.
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to validate role %s during renewal: {{err}}", roleName), err)
	}
	if role == nil {
		return nil, fmt.Errorf("role %s does not exist during renewal", roleName)
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = role.TTL
	resp.Auth.MaxTTL = role.MaxTTL
	resp.Auth.Period = role.Period
	return resp, nil
}

const (
	pathLoginHelpSyn = `
	Authenticates to Vault using a JWT (or OIDC) token.
	`
	pathLoginHelpDesc = `
Authenticates JWTs.
`
)
