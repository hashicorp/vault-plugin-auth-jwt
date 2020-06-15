package jwtauth

import (
	"fmt"
)

// Provider-specific configuration interfaces
// All providers must implement the CustomProvider interface, and may implement
// others as needed.

// ProviderMap is used to map a provider name to its provider type
var ProviderMap = map[string]CustomProvider{
	// TODO: remove "empty" provider when actual providers are added
	"empty": &EmptyProvider{},
}

// CustomProvider - Any custom provider must implement this interface
type CustomProvider interface {
	Initialize(*jwtConfig) error
	SensitiveKeys() []string
}

// NewProviderConfig - returns appropriate provider struct if provider_config
// specified in jwtConfig. The provider map is provider name-to-instance of a
// CustomProvider.
func NewProviderConfig(jc *jwtConfig, providerMap map[string]CustomProvider) (CustomProvider, error) {
	var provider string
	var ok bool
	var newCustomProvider CustomProvider

	if len(jc.ProviderConfig) == 0 {
		return nil, nil
	}
	if provider, ok = jc.ProviderConfig["provider"].(string); !ok {
		return nil, fmt.Errorf("provider field not found in provider_config")
	}
	newCustomProvider, ok = providerMap[provider]
	if !ok {
		return nil, fmt.Errorf("provider %q not found in custom providers", provider)
	}
	err := newCustomProvider.Initialize(jc)
	if err != nil {
		return nil, fmt.Errorf("error initializing %q provider_config: %s", provider, err)
	}
	return newCustomProvider, nil
}

// Example interfaces that are implemented by one or more provider types
// // UserInfoFetcher - Optional support for custom UserInfo handling
// type UserInfoFetcher interface {
// 	FetchUserInfo(context.Context, *oidc.Provider, *oauth2.Token, claims) error
// }

// // GroupsFetcher - Optional support for custom groups handling
// type GroupsFetcher interface {
// 	FetchGroups(context.Context, *oauth2.Token, claims) error
// }
