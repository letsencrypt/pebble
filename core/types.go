package core

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/letsencrypt/pebble/acme"
	"gopkg.in/square/go-jose.v2"
)

type Order struct {
	acme.Order
	ID        string
	ParsedCSR *x509.CertificateRequest
}

type Registration struct {
	acme.Registration
	ID string
}

type Authorization struct {
	acme.Authorization
	ID          string
	URL         string
	ExpiresDate time.Time
}

type Challenge struct {
	acme.Challenge
	ID            string
	Authz         *Authorization
	ValidatedDate time.Time
}

func (ch Challenge) ExpectedKeyAuthorization(key *jose.JSONWebKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("Cannot authorize a nil key")
	}

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	return ch.Token + "." + base64.RawURLEncoding.EncodeToString(thumbprint), nil
}
