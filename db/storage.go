package db

import "github.com/letsencrypt/pebble/core"

type Storage interface {
	// GetAccountByID returns the account corresponding to an ID
	GetAccountByID(string) *core.Account

	// AddAccount stores a new account
	AddAccount(*core.Account) (int, error)

	// AddOrder stores a new order
	AddOrder(*core.Order) (int, error)

	// GetOrderByID returns the order corresponding to an ID
	GetOrderByID(string) *core.Order

	// AddAuthorization stores a new authorization
	AddAuthorization(*core.Authorization) (int, error)

	// GetAuthorizationByID returns the authorization
	// corresponding to an ID
	GetAuthorizationByID(string) *core.Authorization

	// AddChallenge stores a new challenge
	AddChallenge(*core.Challenge) (int, error)

	// GetChallengeByID returns the chanllenge corresponding
	// to an ID
	GetChallengeByID(string) *core.Challenge

	// AddCertificate stores a new certificate
	AddCertificate(*core.Certificate) (int, error)

	// GetCertificateByID returns a certificate corresponding
	// to an ID
	GetCertificateByID(string) *core.Certificate
}
