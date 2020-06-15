package jwtauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	log "github.com/hashicorp/go-hclog"
	"github.com/mitchellh/pointerstructure"
)

// AzureProvider is used for Azure-specific configuration
type AzureProvider struct{}

func (a *AzureProvider) Initialize(jc *jwtConfig) error {
	return nil
}

func (a *AzureProvider) SensitiveKeys() []string {
	return []string{}
}

func (a *AzureProvider) FetchGroups(b *jwtAuthBackend, allClaims map[string]interface{}, role *jwtRole) (interface{}, error) {
	groupsClaimRaw := getClaim(b.Logger(), allClaims, role.GroupsClaim)

	if groupsClaimRaw == nil {
		azureClaimSourcesURL := getClaimSources(b.Logger(), allClaims, b.cachedConfig)
		if azureClaimSourcesURL == "" {
			return nil, fmt.Errorf("%q claim not found in token: %v", role.GroupsClaim, err)
		}

		azureGroups, err := getAzureGroups(b.Logger(), azureClaimSourcesURL, b.cachedConfig)
		if err != nil {
			return nil, fmt.Errorf("%q claim not found in token: %v", role.GroupsClaim, err)
		}
		groupsClaimRaw = azureGroups
	}
	return groupsClaimRaw, nil
}

// This is just a fix for Azure. In Azure, if you are indirectly member of more
// than 200 groups, they will sent you a _claim_sources instead of the groups
func getClaimSources(logger log.Logger, allClaims map[string]interface{}, c *jwtConfig) string {
	claim := "/_claim_sources/src1/endpoint"
	val, err := pointerstructure.Get(allClaims, claim)
	if err != nil {
		logger.Warn(fmt.Sprintf("unable to locate %s in claims: %s", claim, err.Error()))
	}

	logger.Info(fmt.Sprintf("val: %v", val))
	return fmt.Sprintf("%v", val)
}

// Fetch user groups from the Azure AD Graph API
func getAzureGroups(logger log.Logger, url string, c *jwtConfig) (interface{}, error) {
	token, err := getAzureToken(logger, c)
	if err != nil {
		return nil, fmt.Errorf("Unable to get token")
	}

	payload := strings.NewReader("{\"securityEnabledOnly\": false}")
	req, _ := http.NewRequest("POST", url, payload)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("authorization", fmt.Sprintf("Bearer %s", token))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Unable to call ")
	}

	defer res.Body.Close()

	var target azureGroups
	decode := json.NewDecoder(res.Body)
	err = decode.Decode(&target)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode response: %v", err)
	}
	return target.Value, nil
}

// Login to Azure, using client id and secret.
func getAzureToken(logger log.Logger, c *jwtConfig) (string, error) {
	baseURL := "https://login.microsoftonline.com/"
	a := strings.Split(c.OIDCDiscoveryURL, baseURL)
	b := strings.Split(a[1], "/")
	fmt.Println(b[0])

	url := fmt.Sprintf("%s%s/oauth2/v2.0/token", baseURL, b[0])
	scope := "openid profile https://graph.windows.net/.default"
	payload := strings.NewReader(fmt.Sprintf("client_id=%s&scope=%s&client_secret=%s&grant_type=client_credentials", c.OIDCClientID, scope, c.OIDCClientSecret))
	req, _ := http.NewRequest("POST", url, payload)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Unable to call ")
	}

	defer res.Body.Close()

	var target azureToken
	decode := json.NewDecoder(res.Body)
	err = decode.Decode(&target)
	if err != nil {
		return "", fmt.Errorf("Unable to decode response: %v", err)
	}
	return target.AccessToken, nil
}

type azureToken struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	ExtExpiresIn int    `json:"ext_expires_in"`
	AccessToken  string `json:"access_token"`
}
type azureGroups struct {
	Value []interface{} `json:"value"`
}
