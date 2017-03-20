package core

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/letsencrypt/pebble/acme"
	"gopkg.in/square/go-jose.v2"
)

type Order struct {
	acme.Order
	ID                   string
	ParsedCSR            *x509.CertificateRequest
	ExpiresDate          time.Time
	AuthorizationObjects []*Authorization
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
	Order       *Order
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

type Certificate struct {
	ID     string
	Cert   *x509.Certificate
	DER    []byte
	Issuer *Certificate
}

func (c Certificate) PEM() []byte {
	var buf bytes.Buffer

	err := pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.DER,
	})
	if err != nil {
		panic(fmt.Sprintf("Unable to encode certificate %q to PEM: %s",
			c.ID, err.Error()))
	}

	return buf.Bytes()
}

func (c Certificate) Chain() []byte {
	chain := make([][]byte, 0)

	// Add the leaf certificate
	chain = append(chain, c.PEM())

	// Add zero or more issuers
	issuer := c.Issuer
	for {
		// if the issuer is nil, or the issuer's issuer is nil then it isn't a leaf
		// or an intermediate. Don't put it in the chain
		if issuer == nil || issuer.Issuer == nil {
			break
		}
		chain = append(chain, issuer.PEM())
		issuer = issuer.Issuer
	}

	// Return the chain, leaf cert first
	return bytes.Join(chain, []byte{})
}
