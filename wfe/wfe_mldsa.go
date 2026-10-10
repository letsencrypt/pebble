//go:build go1.27

package wfe

import (
	"crypto/mldsa"
	"crypto/x509"

	jose "github.com/go-jose/go-jose/v4"
)

func init() {
	goodSignatureAlgorithms[x509.MLDSA44] = true
	goodSignatureAlgorithms[x509.MLDSA65] = true
	goodSignatureAlgorithms[x509.MLDSA87] = true
}

func mldsaAlgorithmForKey(key *jose.JSONWebKey) string {
	switch k := key.Key.(type) {
	case *mldsa.PublicKey:
		switch k.Parameters() {
		case mldsa.MLDSA44():
			return string(jose.MLDSA44)
		case mldsa.MLDSA65():
			return string(jose.MLDSA65)
		case mldsa.MLDSA87():
			return string(jose.MLDSA87)
		}
	}

	return ""
}
