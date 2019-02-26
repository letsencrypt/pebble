package wfe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/letsencrypt/pebble/acme"

	"gopkg.in/square/go-jose.v2"
)

func algorithmForKey(key *jose.JSONWebKey) (string, error) {
	switch k := key.Key.(type) {
	case *rsa.PublicKey:
		return string(jose.RS256), nil
	case *ecdsa.PublicKey:
		switch k.Params().Name {
		case "P-256":
			return string(jose.ES256), nil
		case "P-384":
			return string(jose.ES384), nil
		case "P-521":
			return string(jose.ES512), nil
		}
	}
	return "", fmt.Errorf("no signature algorithms suitable for given key type: %T", key.Key)
}

// Check that (1) there is a suitable algorithm for the provided key based on its
// Golang type, (2) the Algorithm field on the JWK is either absent, or matches
// that algorithm, and (3) the Algorithm field on the JWK is present and matches
// that algorithm. Precondition: parsedJws must have exactly one signature on
// it.
func checkAlgorithm(key *jose.JSONWebKey, parsedJws *jose.JSONWebSignature) *acme.ProblemDetails {
	algorithm, err := algorithmForKey(key)
	if err != nil {
		return acme.BadPublicKeyProblem(err.Error())
	}
	jwsAlgorithm := parsedJws.Signatures[0].Header.Algorithm
	if jwsAlgorithm != algorithm {
		return acme.MalformedProblem(fmt.Sprintf(
			"signature type '%s' in JWS header is not supported, expected one of RS256, ES256, ES384 or ES512",
			jwsAlgorithm))
	}
	if key.Algorithm != "" && key.Algorithm != algorithm {
		return acme.BadPublicKeyProblem(fmt.Sprintf(
			"algorithm '%s' on JWK is unacceptable", key.Algorithm))
	}
	return nil
}

// keyDigest produces a padded, standard Base64-encoded SHA256 digest of a
// provided public key. See the original Boulder implementation for more details:
// https://github.com/letsencrypt/boulder/blob/9c2859c87b70059a2082fc1f28e3f8a033c66d43/core/util.go#L92
func keyDigest(key crypto.PublicKey) (string, error) {
	switch t := key.(type) {
	case *jose.JSONWebKey:
		if t == nil {
			return "", fmt.Errorf("Cannot compute digest of nil key")
		}
		return keyDigest(t.Key)
	case jose.JSONWebKey:
		return keyDigest(t.Key)
	default:
		keyDER, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", err
		}
		spkiDigest := sha256.Sum256(keyDER)
		return base64.StdEncoding.EncodeToString(spkiDigest[0:32]), nil
	}
}

// keyDigestEquals determines whether two public keys have the same digest.
func keyDigestEquals(j, k crypto.PublicKey) bool {
	digestJ, errJ := keyDigest(j)
	digestK, errK := keyDigest(k)
	// Keys that don't have a valid digest (due to marshaling problems)
	// are never equal. So, e.g. nil keys are not equal.
	if errJ != nil || errK != nil {
		return false
	}
	return digestJ == digestK
}
