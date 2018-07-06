package jwtauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"

	oidc "github.com/coreos/go-oidc"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/oauth2"
)

// Factory is used by framework
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type jwtAuthBackend struct {
	*framework.Backend

	l sync.RWMutex

	provider      *oidc.Provider
	parsedPubKeys atomic.Value
}

func backend(c *logical.BackendConfig) *jwtAuthBackend {
	b := new(jwtAuthBackend)

	b.Backend = &framework.Backend{
		AuthRenew:   b.pathLoginRenew,
		BackendType: logical.TypeCredential,
		Invalidate:  b.invalidate,
		Help:        backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathLogin(b),
				pathConfig(b),
			},
		),
	}

	// Seed the type
	b.parsedPubKeys.Store(([]interface{})(nil))

	return b
}

func (b *jwtAuthBackend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config":
		b.reset()
	}
}

func (b *jwtAuthBackend) reset() {
	b.parsedPubKeys.Store(([]interface{})(nil))
	b.l.Lock()
	b.provider = nil
	b.l.Unlock()
}

func (b *jwtAuthBackend) getProvider(ctx context.Context, config *jwtConfig) (*oidc.Provider, error) {
	b.l.RLock()
	unlockFunc := b.l.RUnlock
	defer func() { unlockFunc() }()

	if b.provider != nil {
		return b.provider, nil
	}

	b.l.RUnlock()
	b.l.Lock()
	unlockFunc = b.l.Unlock

	if b.provider != nil {
		return b.provider, nil
	}

	var certPool *x509.CertPool
	if config.OIDCIssuerCAPEM != "" {
		certPool = x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM([]byte(config.OIDCIssuerCAPEM)); !ok {
			return nil, errors.New("could not parse 'oidc_issuer_ca_pem' value successfully")
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

	provider, err := oidc.NewProvider(oidcCtx, config.OIDCIssuerURL)
	if err != nil {
		return nil, err
	}

	b.provider = provider
	return b.provider, nil
}

const (
	backendHelp = `
The JWT backend plugin allows authentication using JWTs (including OIDC).
`
)
