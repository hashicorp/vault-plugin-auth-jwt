package jwtauth

import (
	"fmt"
	"strings"

	"github.com/mitchellh/pointerstructure"
)

// getClaim returns a claim value from allClaims given a provided claim string.
// If this string is a valid JSONPointer, it will be interpreted as such to locate
// the claim. Otherwise, the claim string will be used directly.
func getClaim(allClaims map[string]interface{}, claim string) interface{} {
	if !strings.HasPrefix(claim, "/") {
		return allClaims[claim]
	}

	val, err := pointerstructure.Get(allClaims, claim)
	if err != nil {
		return nil
	}

	return val
}

// extractMetadata builds a metadata map from a set of claims and claims mappings.
// The referenced claims must be strings and the claims mappings must be of the structure:
//
//   {
//       "/some/claim/pointer": "metadata_key1",
//       "another_claim": "metadata_key2",
//        ...
//   }
func extractMetadata(allClaims map[string]interface{}, claimMappings map[string]string) (map[string]string, error) {
	metadata := make(map[string]string)
	for source, target := range claimMappings {
		if value := getClaim(allClaims, source); value != nil {
			strValue, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("error converting claim '%s' to string", source)
			}

			metadata[target] = strValue
		}
	}
	return metadata, nil
}
