package jwtauth

import (
	"github.com/mitchellh/mapstructure"
)

type JWKSPair struct {
	JWKSUrl   string `mapstructure:"jwks_url"`
	JWKSCAPEM string `mapstructure:"jwks_ca_pem"`
}

func NewJWKSPairsConfig(jc *jwtConfig) ([]*JWKSPair, error) {
	if len(jc.JWKSPairs) <= 0 {
		return nil, nil
	}

	pairs := make([]*JWKSPair, 0, len(jc.JWKSPairs))
	for i := 0; i < len(jc.JWKSPairs); i++ {
		jp, err := Initialize(jc.JWKSPairs[i].(map[string]interface{}))
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, jp)
	}

	return pairs, nil
}

func Initialize(jp map[string]interface{}) (*JWKSPair, error) {
	var newJp JWKSPair
	if err := mapstructure.Decode(jp, &newJp); err != nil {
		return nil, err
	}

	return &newJp, nil
}
