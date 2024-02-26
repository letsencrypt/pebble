package db

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/core"
	"gopkg.in/square/go-jose.v2"
	"math/big"
)

// ExistingAccountError is an error type indicating when an operation fails
// because the MatchingAccount has a key conflict.
type ExistingAccountError struct {
	MatchingAccount *core.Account
}

func (e ExistingAccountError) Error() string {
	return fmt.Sprintf("New public key is already in use by account %s", e.MatchingAccount.ID)
}

/*
 * KeyToID produces a string with the hex representation of the SHA256 digest
 * over a provided public key. We use this to associate public keys to
 * acme.Account objects, and to ensure every account has a unique public key.
 */
func KeyToID(key crypto.PublicKey) (string, error) {
	switch t := key.(type) {
	case *jose.JSONWebKey:
		if t == nil {
			return "", fmt.Errorf("Cannot compute ID of nil key")
		}
		return KeyToID(t.Key)
	case jose.JSONWebKey:
		return KeyToID(t.Key)
	default:
		keyDER, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", err
		}
		spkiDigest := sha256.Sum256(keyDER)
		return hex.EncodeToString(spkiDigest[:]), nil
	}
}

// Pebble keeps all of its various objects (accounts, orders, etc)
// in-memory, not persisted anywhere. MemoryStore implements this in-memory
// "database"
type Store interface {
	GetAccountByID(id string) *core.Account
	GetAccountByKey(key crypto.PublicKey) (*core.Account, error)
	UpdateAccountByID(id string, acct *core.Account) error
	AddAccount(acct *core.Account) (int, error)
	ChangeAccountKey(acct *core.Account, newKey *jose.JSONWebKey) error
	AddOrder(order *core.Order) (int, error)
	GetOrderByID(id string) *core.Order
	GetOrdersByAccountID(accountID string) []*core.Order
	AddAuthorization(authz *core.Authorization) (int, error)
	GetAuthorizationByID(id string) *core.Authorization
	FindValidAuthorization(accountID string, identifier acme.Identifier) *core.Authorization
	AddChallenge(chal *core.Challenge) (int, error)
	GetChallengeByID(id string) *core.Challenge
	AddCertificate(cert *core.Certificate) (int, error)
	GetCertificateByID(id string) *core.Certificate
	GetCertificateByDER(der []byte) *core.Certificate
	GetRevokedCertificateByDER(der []byte) *core.RevokedCertificate
	RevokeCertificate(cert *core.RevokedCertificate)
	GetCertificateBySerial(serialNumber *big.Int) *core.Certificate
	GetRevokedCertificateBySerial(serialNumber *big.Int) *core.RevokedCertificate
	AddExternalAccountKeyByID(keyID, key string) error
	GetExternalAccountKeyByID(keyID string) ([]byte, bool)
	AddBlockedDomain(name string) error
	IsDomainBlocked(name string) bool
}
