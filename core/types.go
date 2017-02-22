package core

import (
	"crypto/x509"

	"github.com/letsencrypt/pebble/acme"
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
	ID string
}

type Challenge struct {
	acme.Challenge
	ID string
}
