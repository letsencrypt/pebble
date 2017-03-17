package core

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
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
	Key *jose.JSONWebKey `json:"key"`
	ID  string
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

func (ch Challenge) ExpectedKeyAuthorization(key *jose.JSONWebKey) string {
	if key == nil {
		panic("ExpectedKeyAuthorization called with nil key")
	}

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		panic("ExpectedKeyAuthorization: " + err.Error())
	}

	return ch.Token + "." + base64.RawURLEncoding.EncodeToString(thumbprint)
}
