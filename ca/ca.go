package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
	"time"

	"github.com/letsencrypt/pebble/core"
	"github.com/letsencrypt/pebble/db"
)

const (
	rootCAPrefix         = "Pebble Root CA "
	intermediateCAPrefix = "Pebble Intermediate CA "
)

type CAImpl struct {
	log *log.Logger
	db  *db.MemoryStore

	root         *issuer
	intermediate *issuer
}

type issuer struct {
	key  crypto.Signer
	cert *core.Certificate
}

func makeSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(fmt.Sprintf("unable to create random serial number: %s", err.Error()))
	}
	return serial
}

// makeKey and makeRootCert are adapted from MiniCA:
// https://github.com/jsha/minica/blob/3a621c05b61fa1c24bcb42fbde4b261db504a74f/main.go

// makeKey creates a new 2048 bit RSA private key
func makeKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (ca *CAImpl) makeRootCert(
	subjectKey crypto.Signer,
	subjCNPrefix string,
	signer *issuer) (*core.Certificate, error) {

	serial := makeSerial()
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: subjCNPrefix + hex.EncodeToString(serial.Bytes()[:3]),
		},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(30, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:           true,
		MaxPathLenZero: true,
	}

	var signerKey crypto.Signer
	if signer != nil && signer.key != nil {
		signerKey = signer.key
	} else {
		signerKey = subjectKey
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, subjectKey.Public(), signerKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	hexSerial := hex.EncodeToString(cert.SerialNumber.Bytes())
	newCert := &core.Certificate{
		ID:   hexSerial,
		Cert: cert,
		DER:  der,
	}
	if signer != nil && signer.cert != nil {
		newCert.Issuer = signer.cert
	}
	_, err = ca.db.AddCertificate(newCert)
	if err != nil {
		return nil, err
	}
	return newCert, nil
}

func (ca *CAImpl) newRootIssuer() {
	// Make a root private key
	rk, err := makeKey()
	if err != nil {
		panic(fmt.Sprintf("Unable to create a new root private key: %s", err.Error()))
	}
	// Make a self-signed root certificate
	rc, err := ca.makeRootCert(rk, rootCAPrefix, nil)
	if err != nil {
		panic(fmt.Sprintf("Unable to create a new root certificate: %s", err.Error()))
	}

	ca.root = &issuer{
		key:  rk,
		cert: rc,
	}
	ca.log.Printf("Generated new root issuer with serial %s\n", rc.ID)
}

func (ca *CAImpl) newIntermediateIssuer() {
	if ca.root == nil {
		panic("error: newIntermediateIssuer() called before newRootIssuer()")
	}

	// Make an intermediate private key
	ik, err := makeKey()
	if err != nil {
		panic(fmt.Sprintf(
			"Unable to create a new intermediate private key: %s", err.Error()))
	}

	// Make an intermediate certificate with the root issuer
	ic, err := ca.makeRootCert(ik, intermediateCAPrefix, ca.root)
	if err != nil {
		panic(fmt.Sprintf("Unable to create a new intermediate certificate: %s", err.Error()))
	}
	ca.intermediate = &issuer{
		key:  ik,
		cert: ic,
	}
	ca.log.Printf("Generated new intermediate issuer with serial %s\n", ic.ID)
}

func (ca *CAImpl) NewCertificate(domains []string, key crypto.PublicKey) (*core.Certificate, error) {
	var cn string
	if len(domains) > 0 {
		cn = domains[0]
	} else {
		return nil, fmt.Errorf("must specify at least one domain name")
	}

	issuer := ca.intermediate
	if issuer == nil || issuer.cert == nil {
		return nil, fmt.Errorf("cannot sign certificate - nil issuer")
	}

	serial := makeSerial()
	template := &x509.Certificate{
		DNSNames: domains,
		Subject: pkix.Name{
			CommonName: cn,
		},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(5, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA: false,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert.Cert, key, issuer.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	hexSerial := hex.EncodeToString(cert.SerialNumber.Bytes())
	newCert := &core.Certificate{
		ID:     hexSerial,
		Cert:   cert,
		DER:    der,
		Issuer: issuer.cert,
	}
	_, err = ca.db.AddCertificate(newCert)
	if err != nil {
		return nil, err
	}
	return newCert, nil
}

func New(log *log.Logger, db *db.MemoryStore) *CAImpl {
	ca := &CAImpl{
		log: log,
		db:  db,
	}
	ca.newRootIssuer()
	ca.newIntermediateIssuer()
	return ca
}
