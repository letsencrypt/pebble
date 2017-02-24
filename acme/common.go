package acme

import (
	"gopkg.in/square/go-jose.v1"
)

// acme.Resource values identify different types of ACME resources
type Resource string

const (
	ResourceNewNonce = Resource("new-nonce")
	ResourceNewReg   = Resource("new-reg")
	ResourceNewOrder = Resource("new-order")
)

const (
	StatusPending = "pending"

	IdentifierDNS = "dns"

	ChallengeHTTP01 = "http-01"
)

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// TODO(@cpu) - Rename Registration to Account, update refs
type Registration struct {
	Status    string           `json:"status"`
	Key       *jose.JsonWebKey `json:"key"`
	Contact   []string         `json:"contact"`
	ToSAgreed bool             `json:"terms-of-service-agreed"`
	Orders    string           `json:"orders"`
}

// An Order is created to request issuance for a CSR
type Order struct {
	Status         string   `json:"status"`
	Expires        string   `json:"expires"`
	CSR            string   `json:"csr"`
	NotBefore      string   `json:"notBefore"`
	NotAfter       string   `json:"notAfter"`
	Authorizations []string `json:"authorizations"`
	Certificate    string   `json:"certificate,omitempty"`
}

// An Authorization is created for each identifier in an order
type Authorization struct {
	Status     string     `json:"status"`
	Identifier Identifier `json:"identifier"`
	Challenges []string   `json:"challenges"`
}

// A Challenge is used to validate an Authorization
type Challenge struct {
	Type  string `json:"type"`
	URL   string `json:"url"`
	Token string `json:"token"`
}
