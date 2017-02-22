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

type Status string

const (
	StatusPending = Status("pending")
)

type IdentifierType string

const (
	IdentifierDNS = IdentifierType("dns")
)

type ChallengeType string

const (
	ChallengeHTTP01 = ChallengeType("http-01")
)

type Identifier struct {
	Type  IdentifierType `json:"type"`
	Value string         `json:"value"`
}

// TODO(@cpu) - Rename Registration to Account, update refs
type Registration struct {
	Status    Status           `json:"status"`
	Key       *jose.JsonWebKey `json:"key"`
	Contact   []string         `json:"contact"`
	ToSAgreed bool             `json:"terms-of-service-agreed"`
	Orders    string           `json:"orders"`
}

// Order is used for new-order requests
type Order struct {
	Status         Status   `json:"status"`
	Expires        string   `json:"expires"`
	CSR            string   `json:"csr"`
	NotBefore      string   `json:"notBefore"`
	NotAfter       string   `json:"notAfter"`
	Authorizations []string `json:"authorizations"`
	Certificate    string   `json:"certificate,omitempty"`
}

// An Authorization is created for each identifier in an order
type Authorization struct {
	Status     Status     `json:"status"`
	Identifier Identifier `json:"identifier"`
	Challenges []string   `json:"challenges"`
}

// A Challenge is used to validate an Authorization
type Challenge struct {
	Type  ChallengeType `json:"type"`
	URL   string        `json:"url"`
	Token string        `json:"token"`
}
