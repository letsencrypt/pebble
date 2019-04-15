package core

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/letsencrypt/pebble/acme"
	"gopkg.in/square/go-jose.v2"
)

type Order struct {
	sync.RWMutex
	acme.Order
	ID                   string
	AccountID            string
	Names                []string
	ParsedCSR            *x509.CertificateRequest
	ExpiresDate          time.Time
	AuthorizationObjects []*Authorization
	BeganProcessing      bool
	CertificateObject    *Certificate
}

func (o *Order) GetStatus() (string, error) {
	// Lock the order for reading
	o.RLock()
	defer o.RUnlock()

	// If the order has an error set, the status is invalid
	if o.Error != nil {
		return acme.StatusInvalid, nil
	}

	authzStatuses := make(map[string]int)

	for _, authz := range o.AuthorizationObjects {
		// Lock the authorization for reading
		authz.RLock()
		authzStatus := authz.Status
		authzExpires := authz.ExpiresDate
		authz.RUnlock()

		authzStatuses[authzStatus]++

		if authzExpires.Before(time.Now()) {
			authzStatuses[acme.StatusExpired]++
		}
	}

	// An order is invalid if **any** of its authzs are invalid
	if authzStatuses[acme.StatusInvalid] > 0 {
		return acme.StatusInvalid, nil
	}

	// An order is expired if **any** of its authzs are expired
	if authzStatuses[acme.StatusExpired] > 0 {
		return acme.StatusInvalid, nil
	}

	// An order is deactivated if **any** of its authzs are deactivated
	if authzStatuses[acme.StatusDeactivated] > 0 {
		return acme.StatusDeactivated, nil
	}

	// An order is pending if **any** of its authzs are pending
	if authzStatuses[acme.StatusPending] > 0 {
		return acme.StatusPending, nil
	}

	fullyAuthorized := len(o.Names) == authzStatuses[acme.StatusValid]

	// If the order isn't fully authorized we've encountered an internal error:
	// Above we checked for any invalid or pending authzs and should have returned
	// early. Somehow we made it this far but also don't have the correct number
	// of valid authzs.
	if !fullyAuthorized {
		return "", fmt.Errorf(
			"Order has the incorrect number of valid authorizations & no pending, " +
				"deactivated or invalid authorizations")
	}

	// If the order is fully authorized and the certificate serial is set then the
	// order is valid
	if fullyAuthorized && o.CertificateObject != nil {
		return acme.StatusValid, nil
	}

	// If the order is fully authorized, and we have began processing it, then the
	// order is processing.
	if fullyAuthorized && o.BeganProcessing {
		return acme.StatusProcessing, nil
	}

	// If the order is fully authorized, and we haven't begun processing it, then
	// the order is pending finalization and status ready.
	if fullyAuthorized && !o.BeganProcessing {
		return acme.StatusReady, nil
	}

	// If none of the above cases match something weird & unexpected has happened.
	return "", fmt.Errorf("Order is in an unknown state")
}

type Account struct {
	acme.Account
	Key *jose.JSONWebKey `json:"key"`
	ID  string           `json:"-"`
}

type Authorization struct {
	sync.RWMutex
	acme.Authorization
	ID          string
	URL         string
	ExpiresDate time.Time
	Order       *Order
	Challenges  []*Challenge
}

type Challenge struct {
	sync.RWMutex
	acme.Challenge
	ID            string
	Authz         *Authorization
	ValidatedDate time.Time
}

func (ch *Challenge) ExpectedKeyAuthorization(key *jose.JSONWebKey) string {
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
	ID        string
	Cert      *x509.Certificate
	DER       []byte
	Issuer    *Certificate
	AccountID string
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
		// if the issuer is nil, or the issuer's issuer is nil then we've reached
		// the root of the chain and can break
		if issuer == nil || issuer.Issuer == nil {
			break
		}
		chain = append(chain, issuer.PEM())
		issuer = issuer.Issuer
	}

	// Return the chain, leaf cert first
	return bytes.Join(chain, nil)
}

type ValidationRecord struct {
	URL         string
	Error       *acme.ProblemDetails
	ValidatedAt time.Time
}
