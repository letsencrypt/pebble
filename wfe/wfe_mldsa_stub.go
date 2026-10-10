//go:build !go1.27

package wfe

import (
	jose "github.com/go-jose/go-jose/v4"
)

func mldsaAlgorithmForKey(key *jose.JSONWebKey) string {
	return ""
}
