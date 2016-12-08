package acme

import (
	jose "github.com/square/go-jose"
)

// acme.Resource values identify different types of ACME resources
type Resource string

const (
	ResourceNewNonce = Resource("new-nonce")
	ResourceNewReg   = Resource("new-reg")
)

type Registration struct {
	ID           string           `json:"id"`
	Key          *jose.JsonWebKey `json:"key"`
	Contact      []string         `json:"contact,omitempty"`
	ToSAgreed    bool             `json:"terms-of-service-agreed,omitempty"`
	Applications string           `json:"applications,omitempty"`
	Status       string
}
