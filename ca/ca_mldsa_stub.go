//go:build !go1.27

package ca

import (
	"crypto"
	"fmt"
)

// crypto/mldsa is not available before Go 1.27
func mldsaGenerateKey() (crypto.Signer, error) {
	return nil, fmt.Errorf("unsupported key algorithm: mldsa")
}
