//go:build go1.27

package wfe

import (
	"crypto/x509"
)

func init() {
	goodSignatureAlgorithms[x509.MLDSA44] = true
	goodSignatureAlgorithms[x509.MLDSA65] = true
	goodSignatureAlgorithms[x509.MLDSA87] = true
}
