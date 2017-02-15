package acme

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"

	"gopkg.in/square/go-jose.v1"
)

// acme.Resource values identify different types of ACME resources
type Resource string

const (
	ResourceNewNonce = Resource("new-nonce")
	ResourceNewReg   = Resource("new-reg")
	ResourceNewOrder = Resource("new-order")
)

type Status string

const (
	StatusPending = Status("pending")
)

type IdentifierType string

const (
	IdentifierDNS = IdentifierType("dns")
)

type Identifier struct {
	Type  IdentifierType `json:"type"`
	Value string         `json:"value"`
}

// TODO(@cpu) - Rename Registration to Account, update refs
type Registration struct {
	ID        string           `json:"id"`
	Key       *jose.JsonWebKey `json:"key"`
	Contact   []string         `json:"contact"`
	ToSAgreed bool             `json:"terms-of-service-agreed"`
	Orders    string           `json:"orders"`
	Status    Status
}

// OrderRequest is used for new-order requests
type OrderRequest struct {
	ID             string
	Status         Status   `json:"status"`
	Expires        string   `json:"expires"`
	CSR            string   `json:"csr"`
	NotBefore      string   `json:"notBefore"`
	NotAfter       string   `json:"notAfter"`
	Authorizations []string `json:"authorizations"`
	Certificate    string   `json:"certificate,omitempty"`
}

// Order is constructed out of an OrderRequest
type Order struct {
	OrderRequest
	ParsedCSR *x509.CertificateRequest
}

// A Challenge is used to validate an authorization
type Challenge struct {
	Type  string `json:"type"`
	URL   string `json:"url"`
	Token string `json:"token"`
}

// An Authorization is created for each identifier in an order
type Authorization struct {
	ID         string
	Status     Status      `json:"status"`
	Identifier Identifier  `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
}

// RandomString and NewToken come from Boulder core/util.go
// RandomString returns a randomly generated string of the requested length.
func RandomString(byteLength int) string {
	b := make([]byte, byteLength)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(fmt.Sprintf("Error reading random bytes: %s", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewToken produces a random string for Challenges, etc.
func NewToken() string {
	return RandomString(32)
}
