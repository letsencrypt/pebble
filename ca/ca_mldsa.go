//go:build go1.27

package ca

import (
	"crypto"
	"crypto/mldsa"
)

func mldsaGenerateKey() (crypto.Signer, error) {
	return mldsa.GenerateKey(mldsa.MLDSA65())
}
