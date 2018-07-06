package jwtauth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"

	"context"

	oidc "github.com/coreos/go-oidc"
	"github.com/hashicorp/errwrap"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/helper/certutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/oauth2"
)

func pathConfig(b *jwtAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `config`,
		Fields: map[string]*framework.FieldSchema{
			"oidc_issuer_url": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "OIDC issuer URL, without any .well-known component (base path)",
			},
			"oidc_issuer_ca_pem": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The CA certificate or chain of certificates, in PEM format, to use to validate conections to the OIDC issuer URL. If not set, system certificates are used.",
			},
			"jwt_validation_pubkeys": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: "When performing local validation on a JWT, a list of PEM-encoded public keys to use to authenticate the JWT's signature.",
			},
			"bound_issuer": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The value against which to match the 'iss' claim in a JWT. Optional.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigRead,
			logical.UpdateOperation: b.pathConfigWrite,
		},

		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

func (b *jwtAuthBackend) config(ctx context.Context, s logical.Storage) (*jwtConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result jwtConfig
	if entry != nil {
		if err := entry.DecodeJSON(&result); err != nil {
			return nil, err
		}
	}

	pubKeys := b.parsedPubKeys.Load().([]interface{})
	if pubKeys == nil {
		for _, v := range result.JWTValidationPubKeys {
			key, err := certutil.ParsePublicKeyPEM([]byte(v))
			if err != nil {
				return nil, errwrap.Wrapf("error parsing public key: {{err}}", err)
			}
			pubKeys = append(pubKeys, key)
		}
		b.parsedPubKeys.Store(pubKeys)
	}
	result.ParsedJWTPubKeys = pubKeys

	return &result, nil
}

func (b *jwtAuthBackend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"oidc_issuer_url":        config.OIDCIssuerURL,
			"oidc_issuer_ca_pem":     config.OIDCIssuerCAPEM,
			"jwt_validation_pubkeys": config.JWTValidationPubKeys,
			"bound_issuer":           config.BoundIssuer,
		},
	}

	return resp, nil
}

func (b *jwtAuthBackend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config := &jwtConfig{
		OIDCIssuerURL:        d.Get("oidc_issuer_url").(string),
		OIDCIssuerCAPEM:      d.Get("oidc_issuer_ca_pem").(string),
		JWTValidationPubKeys: d.Get("jwt_validation_pubkeys").([]string),
		BoundIssuer:          d.Get("bound_issuer").(string),
	}

	// Run checks on values
	switch {
	case config.OIDCIssuerURL == "" && len(config.JWTValidationPubKeys) == 0,
		config.OIDCIssuerURL != "" && len(config.JWTValidationPubKeys) != 0:
		return logical.ErrorResponse("exactly one of 'oidc_issuer_url' and 'jwt_validation_pubkeys' must be set"), nil

	case config.OIDCIssuerURL != "":
		var certPool *x509.CertPool
		if config.OIDCIssuerCAPEM != "" {
			certPool = x509.NewCertPool()
			if ok := certPool.AppendCertsFromPEM([]byte(config.OIDCIssuerCAPEM)); !ok {
				return logical.ErrorResponse("could not parse 'oidc_issuer_ca_pem' value successfully"), nil
			}
		}

		tr := cleanhttp.DefaultPooledTransport()
		if certPool != nil {
			tr.TLSClientConfig = &tls.Config{
				RootCAs: certPool,
			}
		}
		tc := &http.Client{
			Transport: tr,
		}
		oidcCtx := context.WithValue(ctx, oauth2.HTTPClient, tc)

		if _, err := oidc.NewProvider(oidcCtx, config.OIDCIssuerURL); err != nil {
			return logical.ErrorResponse(errwrap.Wrapf("error creating provider with given values: {{err}}", err).Error()), nil
		}

	case len(config.JWTValidationPubKeys) != 0:
		for _, v := range config.JWTValidationPubKeys {
			if _, err := certutil.ParsePublicKeyPEM([]byte(v)); err != nil {
				return logical.ErrorResponse(errwrap.Wrapf("error parsing public key: {{err}}", err).Error()), nil
			}
		}

	default:
		return nil, errors.New("unknown condition")
	}

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

type jwtConfig struct {
	OIDCIssuerURL        string   `json:"oidc_issuer_url"`
	OIDCIssuerCAPEM      string   `json:"oidc_issuer_ca_pem"`
	JWTValidationPubKeys []string `json:"jwt_validation_pubkeys"`
	BoundIssuer          string   `json:"bound_issuer"`

	ParsedJWTPubKeys []interface{} `json:"-"`
}

const (
	confHelpSyn = `
Configures the JWT authentication backend.
`
	confHelpDesc = `
The JWT authentication backend validates JWTs (or OIDC) using the configured
credentials. If using OIDC issuer discovery, the URL must be provided, along
with (optionally) the CA cert to use for the connection. If performing JWT
validation locally, a set of public keys must be provided.
`
)
