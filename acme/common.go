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

// TODO(@cpu) - Rename Registration to Account, update refs
type Registration struct {
	ID        string           `json:"id"`
	Key       *jose.JsonWebKey `json:"key"`
	Contact   []string         `json:"contact,omitempty"`
	ToSAgreed bool             `json:"terms-of-service-agreed,omitempty"`
	Orders    string           `json:"orders,omitempty"`
	Status    string
}

// OrderRequest is used for new-order requests
type OrderRequest struct {
	ID             string   `json:"id"`
	Status         string   `json:"status"`
	Expires        string   `json:"expires"`
	CSR            string   `json:"csr"`
	NotBefore      string   `json:"notBefore"`
	NotAfter       string   `json:"notAfter"`
	Authorizations []string `json:authorizations,omitempty"`
	Certificate    string   `json:certificate,omitempty"`
}

// Order is constructed out of an OrderRequest and is an internal type
type Order struct {
	OrderRequest
	ParsedCSR *x509.CertificateRequest
}

// TODO(@cpu): Create an "Authorizations" type

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
