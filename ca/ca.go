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
	"net"
	"time"

	"github.com/letsencrypt/pebble/acme"
	"github.com/letsencrypt/pebble/core"
	"github.com/letsencrypt/pebble/db"
)

const (
	rootCAPrefix         = "Pebble Root CA "
	intermediateCAPrefix = "Pebble Intermediate CA "
)

type CAImpl struct {
	log              *log.Logger
	db               *db.MemoryStore
	ocspResponderURL string

	mainChain         *chain
	alternativeChains []*chain
}

type chain struct {
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

func makeRootCert(
	ca *CAImpl,
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
		IsCA:                  true,
	}

	var signerKey crypto.Signer
	var parent *x509.Certificate
	if signer != nil && signer.key != nil && signer.cert != nil && signer.cert.Cert != nil {
		signerKey = signer.key
		parent = signer.cert.Cert
	} else {
		signerKey = subjectKey
		parent = template
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, subjectKey.Public(), signerKey)
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

func newRootIssuer(ca *CAImpl) (*issuer, error) {
	// Make a root private key
	rk, err := makeKey()
	if err != nil {
		return nil, err
	}
	// Make a self-signed root certificate
	rc, err := makeRootCert(ca, rk, rootCAPrefix, nil)
	if err != nil {
		return nil, err
	}

	ca.log.Printf("Generated new root issuer with serial %s\n", rc.ID)
	return &issuer{
		key:  rk,
		cert: rc,
	}, nil
}

func (chain *chain) newIntermediateIssuer(ca *CAImpl, ik crypto.Signer) error {
	if chain.root == nil {
		return fmt.Errorf("newIntermediateIssuer() called before newRootIssuer()")
	}

	// Make an intermediate certificate with the root issuer
	ic, err := makeRootCert(ca, ik, intermediateCAPrefix, chain.root)
	if err != nil {
		return err
	}
	chain.intermediate = &issuer{
		key:  ik,
		cert: ic,
	}
	ca.log.Printf("Generated new intermediate issuer with serial %s\n", ic.ID)
	return nil
}

func newChain(ca *CAImpl, ik crypto.Signer) *chain {
	chain := &chain{}
	root, err := newRootIssuer(ca)
	if err != nil {
		panic(fmt.Sprintf("Error creating new root issuer: %s", err.Error()))
	}
	chain.root = root
	if err := chain.newIntermediateIssuer(ca, ik); err != nil {
		panic(fmt.Sprintf("Error creating new intermediate issuer: %s", err.Error()))
	}
	return chain
}

func (ca *CAImpl) newCertificate(domains []string, ips []net.IP, key crypto.PublicKey, accountID string) (*core.Certificate, error) {
	var cn string
	if len(domains) > 0 {
		cn = domains[0]
	} else if len(ips) > 0 {
		cn = ips[0].String()
	} else {
		return nil, fmt.Errorf("must specify at least one domain name or IP address")
	}

	issuer := ca.mainChain.intermediate
	if issuer == nil || issuer.cert == nil {
		return nil, fmt.Errorf("cannot sign certificate - nil issuer")
	}

	serial := makeSerial()
	template := &x509.Certificate{
		DNSNames:    domains,
		IPAddresses: ips,
		Subject: pkix.Name{
			CommonName: cn,
		},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(5, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ca.ocspResponderURL != "" {
		template.OCSPServer = []string{ca.ocspResponderURL}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert.Cert, key, issuer.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	altIssuers := make([]*core.Certificate, len(ca.alternativeChains))
	for i := 0; i < len(ca.alternativeChains); i++ {
		altIssuers[i] = ca.alternativeChains[i].intermediate.cert
	}

	hexSerial := hex.EncodeToString(cert.SerialNumber.Bytes())
	newCert := &core.Certificate{
		ID:                 hexSerial,
		AccountID:          accountID,
		Cert:               cert,
		DER:                der,
		Issuer:             issuer.cert,
		AlternativeIssuers: altIssuers,
	}
	_, err = ca.db.AddCertificate(newCert)
	if err != nil {
		return nil, err
	}
	return newCert, nil
}

func New(log *log.Logger, db *db.MemoryStore, ocspResponderURL string, alternateRoots int) *CAImpl {
	ca := &CAImpl{
		log: log,
		db:  db,
	}

	if ocspResponderURL != "" {
		ca.ocspResponderURL = ocspResponderURL
		ca.log.Printf("Setting OCSP responder URL for issued certificates to %q", ca.ocspResponderURL)
	}

	ik, err := makeKey()
	if err != nil {
		panic(fmt.Sprintf("Error creating new intermediate private key: %s", err.Error()))
	}
	ca.mainChain = newChain(ca, ik)

	// Create alternative chains
	ca.alternativeChains = make([]*chain, alternateRoots)
	for i := 0; i < len(ca.alternativeChains); i++ {
		ca.alternativeChains[i] = newChain(ca, ik)
	}
	return ca
}

func (ca *CAImpl) CompleteOrder(order *core.Order) {
	// Lock the order for reading
	order.RLock()
	// If the order isn't set as beganProcessing produce an error and immediately unlock
	if !order.BeganProcessing {
		ca.log.Printf("Error: Asked to complete order %s which had false beganProcessing.",
			order.ID)
		order.RUnlock()
		return
	}
	// Unlock the order again
	order.RUnlock()

	// Check the authorizations - this is done by the VA before calling
	// CompleteOrder but we do it again for robustness sake.
	for _, authz := range order.AuthorizationObjects {
		// Lock the authorization for reading
		authz.RLock()
		if authz.Status != acme.StatusValid {
			return
		}
		authz.RUnlock()
	}

	// issue a certificate for the csr
	csr := order.ParsedCSR
	cert, err := ca.newCertificate(csr.DNSNames, csr.IPAddresses, csr.PublicKey, order.AccountID)
	if err != nil {
		ca.log.Printf("Error: unable to issue order: %s", err.Error())
		return
	}
	ca.log.Printf("Issued certificate serial %s for order %s\n", cert.ID, order.ID)

	// Lock and update the order to store the issued certificate
	order.Lock()
	order.CertificateObject = cert
	order.Unlock()
}

func (ca *CAImpl) GetNumberOfAlternativeRootCerts() int {
	return len(ca.alternativeChains)
}

func (ca *CAImpl) getChain(no int) *chain {
	if no == 0 {
		return ca.mainChain
	} else if 0 < no && no <= len(ca.alternativeChains) {
		return ca.alternativeChains[no-1]
	} else {
		return nil
	}
}

func (ca *CAImpl) GetRootCert(no int) *core.Certificate {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}
	return chain.root.cert
}

func (ca *CAImpl) GetRootKey(no int) *rsa.PrivateKey {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}

	switch key := chain.root.key.(type) {
	case *rsa.PrivateKey:
		return key
	}
	return nil
}

func (ca *CAImpl) GetIntermediateCert(no int) *core.Certificate {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}
	return chain.intermediate.cert
}

func (ca *CAImpl) GetIntermediateKey(no int) *rsa.PrivateKey {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}

	switch key := chain.intermediate.key.(type) {
	case *rsa.PrivateKey:
		return key
	}
	return nil
}
