package core

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/letsencrypt/pebble/v2/acme"
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

	fullyAuthorized := len(o.Identifiers) == authzStatuses[acme.StatusValid]

	// If the order isn't fully authorized we've encountered an internal error:
	// Above we checked for any invalid or pending authzs and should have returned
	// early. Somehow we made it this far but also don't have the correct number
	// of valid authzs.
	if !fullyAuthorized {
		return "", errors.New(
			"order has the incorrect number of valid authorizations & no pending, " +
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
	return "", errors.New("order is in an unknown state")
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
	ID           string
	Cert         *x509.Certificate
	DER          []byte
	IssuerChains [][]*Certificate
	AccountID    string
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

func (c Certificate) Chain(no int) []byte {
	fullchain := make([][]byte, 0)

	// Add the leaf certificate
	fullchain = append(fullchain, c.PEM())

	// Add zero or more intermediates
	var chain []*Certificate
	if 0 <= no && no < len(c.IssuerChains) {
		chain = c.IssuerChains[no]
	}
	for _, cert := range chain {
		fullchain = append(fullchain, cert.PEM())
	}

	// Return the chain, leaf cert first
	return bytes.Join(fullchain, nil)
}

// RevokedCertificate is a certificate together with information about its revocation.
type RevokedCertificate struct {
	Certificate *Certificate
	RevokedAt   time.Time
	Reason      *uint
}

type ValidationRecord struct {
	URL         string
	Error       *acme.ProblemDetails
	ValidatedAt time.Time
}

// SubjectKeyIDs is a convenience type that holds the Subject Key Identifier
// value for each Pebble generated root and intermediate certificate.
type SubjectKeyIDs [][]byte

// CertID represents a unique identifier (CertID) for a certificate as per the
// ACME protocol's "renewalInfo" resource, as specified in draft-ietf-acme-ari-
// 03. The CertID is a composite string derived from the base64url-encoded
// keyIdentifier of the certificate's Authority Key Identifier (AKI) and the
// base64url-encoded serial number of the certificate, separated by a period.
// For more details see:
// https://datatracker.ietf.org/doc/html/draft-ietf-acme-ari-02#section-4.1.
type CertID struct {
	KeyIdentifier []byte
	SerialNumber  *big.Int
}

// SuggestedWindow is a type exposed inside the RenewalInfo resource.
type SuggestedWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// IsWithin returns true if the given time is within the suggested window,
// inclusive of the start time and exclusive of the end time.
func (window SuggestedWindow) IsWithin(now time.Time) bool {
	return !now.Before(window.Start) && now.Before(window.End)
}

// RenewalInfo is a type which is exposed to clients which query the renewalInfo
// endpoint specified in draft-aaron-ari.
type RenewalInfo struct {
	SuggestedWindow SuggestedWindow `json:"suggestedWindow"`
}

// RenewalInfoSimple constructs a `RenewalInfo` object and suggested window
// using a very simple renewal calculation: calculate a point 2/3rds of the way
// through the validity period, then give a 2-day window around that. Both the
// `issued` and `expires` timestamps are expected to be UTC.
func RenewalInfoSimple(issued time.Time, expires time.Time) *RenewalInfo {
	validity := expires.Add(time.Second).Sub(issued)
	renewalOffset := validity / time.Duration(3)
	idealRenewal := expires.Add(-renewalOffset)
	return &RenewalInfo{
		SuggestedWindow: SuggestedWindow{
			Start: idealRenewal.Add(-24 * time.Hour),
			End:   idealRenewal.Add(24 * time.Hour),
		},
	}
}

// RenewalInfoImmediate constructs a `RenewalInfo` object with a suggested
// window in the past. Per the draft-ietf-acme-ari-01 spec, clients should
// attempt to renew immediately if the suggested window is in the past. The
// passed `now` is assumed to be a timestamp representing the current moment in
// time.
func RenewalInfoImmediate(now time.Time) *RenewalInfo {
	oneHourAgo := now.Add(-1 * time.Hour)
	return &RenewalInfo{
		SuggestedWindow: SuggestedWindow{
			Start: oneHourAgo,
			End:   oneHourAgo.Add(time.Minute * 30),
		},
	}
}
