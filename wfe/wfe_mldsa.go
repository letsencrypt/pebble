//go:build go1.27

package wfe

import (
	"crypto/mldsa"
	"crypto/x509"
)

type mldsaPublicKey = mldsa.PublicKey

func init() {
	goodSignatureAlgorithms[x509.MLDSA44] = true
	goodSignatureAlgorithms[x509.MLDSA65] = true
	goodSignatureAlgorithms[x509.MLDSA87] = true
}
