package ca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
)

const (
	rootCAPrefix          = "Pebble Root CA "
	intermediateCAPrefix  = "Pebble Intermediate CA "
	defaultValidityPeriod = 157766400
)

type CAImpl struct {
	log              *log.Logger
	db               *db.MemoryStore
	ocspResponderURL string

	chains []*chain

	certValidityPeriod uint64
}

type chain struct {
	root          *issuer
	intermediates []*issuer
}

func (c *chain) String() string {
	fullchain := append(c.intermediates, c.root)
	n := len(fullchain)

	names := make([]string, n)
	for i := range fullchain {
		names[n-i-1] = fullchain[i].cert.Cert.Subject.CommonName
	}
	return strings.Join(names, " -> ")
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

// Taken from https://github.com/cloudflare/cfssl/blob/b94e044bb51ec8f5a7232c71b1ed05dbe4da96ce/signer/signer.go#L221-L244
func makeSubjectKeyID(key crypto.PublicKey) ([]byte, error) {
	// Marshal the public key as ASN.1
	pubAsDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	// Unmarshal it again so we can extract the key bitstring bytes
	var pubInfo struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(pubAsDER, &pubInfo)
	if err != nil {
		return nil, err
	}

	// Hash it according to https://tools.ietf.org/html/rfc5280#section-4.2.1.2 Method #1:
	ski := sha1.Sum(pubInfo.SubjectPublicKey.Bytes)
	return ski[:], nil
}

// makeKey and makeRootCert are adapted from MiniCA:
// https://github.com/jsha/minica/blob/3a621c05b61fa1c24bcb42fbde4b261db504a74f/main.go

// makeKey creates a new 2048 bit RSA private key and a Subject Key Identifier
func makeKey() (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	ski, err := makeSubjectKeyID(key.Public())
	if err != nil {
		return nil, nil, err
	}
	return key, ski, nil
}

func (ca *CAImpl) makeCACert(
	subjectKey crypto.Signer,
	subject pkix.Name,
	subjectKeyID []byte,
	signer *issuer,
) (*core.Certificate, error) {
	serial := makeSerial()
	template := &x509.Certificate{
		Subject:      subject,
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(30, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          subjectKeyID,
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
		newCert.IssuerChains = make([][]*core.Certificate, 1)
		newCert.IssuerChains[0] = []*core.Certificate{signer.cert}
	}
	_, err = ca.db.AddCertificate(newCert)
	if err != nil {
		return nil, err
	}
	return newCert, nil
}

func (ca *CAImpl) newRootIssuer(name string) (*issuer, error) {
	// Make a root private key
	rk, subjectKeyID, err := makeKey()
	if err != nil {
		return nil, err
	}
	// Make a self-signed root certificate
	subject := pkix.Name{
		CommonName: rootCAPrefix + name,
	}
	rc, err := ca.makeCACert(rk, subject, subjectKeyID, nil)
	if err != nil {
		return nil, err
	}

	ca.log.Printf("Generated new root issuer %s with serial %s and SKI %x\n", rc.Cert.Subject, rc.ID, subjectKeyID)
	return &issuer{
		key:  rk,
		cert: rc,
	}, nil
}

func (ca *CAImpl) newIntermediateIssuer(root *issuer, intermediateKey crypto.Signer, subject pkix.Name, subjectKeyID []byte) (*issuer, error) {
	if root == nil {
		return nil, errors.New("internal error: root must not be nil")
	}
	// Make an intermediate certificate with the root issuer
	ic, err := ca.makeCACert(intermediateKey, subject, subjectKeyID, root)
	if err != nil {
		return nil, err
	}
	ca.log.Printf("Generated new intermediate issuer %s with serial %s and SKI %x\n", ic.Cert.Subject, ic.ID, subjectKeyID)
	return &issuer{
		key:  intermediateKey,
		cert: ic,
	}, nil
}

// newChain generates a new issuance chain, including a root certificate and numIntermediates intermediates (at least 1).
// The first intermediate will use intermediateKey, intermediateSubject and subjectKeyId.
// Any intermediates between the first intermediate and the root will have their keys and subjects generated automatically.
func (ca *CAImpl) newChain(intermediateKey crypto.Signer, intermediateSubject pkix.Name, subjectKeyID []byte, numIntermediates int) *chain {
	if numIntermediates <= 0 {
		panic("At least one intermediate must be present in the certificate chain")
	}

	chainID := hex.EncodeToString(makeSerial().Bytes()[:3])

	root, err := ca.newRootIssuer(chainID)
	if err != nil {
		panic(fmt.Sprintf("Error creating new root issuer: %s", err.Error()))
	}

	// The last N-1 intermediates build a path from the root to the leaf signing certificate.
	// If numIntermediates is only 1, then no intermediates will be generated here.
	prev := root
	intermediates := make([]*issuer, numIntermediates)
	for i := numIntermediates - 1; i > 0; i-- {
		k, ski, err := makeKey()
		if err != nil {
			panic(fmt.Sprintf("Error creating new intermediate issuer: %v", err))
		}
		intermediate, err := ca.newIntermediateIssuer(prev, k, pkix.Name{
			CommonName: fmt.Sprintf("%s%s #%d", intermediateCAPrefix, chainID, i),
		}, ski)
		if err != nil {
			panic(fmt.Sprintf("Error creating new intermediate issuer: %s", err.Error()))
		}
		intermediates[i] = intermediate
		prev = intermediate
	}

	// The first issuer is the one which signs the leaf certificates
	intermediate, err := ca.newIntermediateIssuer(prev, intermediateKey, intermediateSubject, subjectKeyID)
	if err != nil {
		panic(fmt.Sprintf("Error creating new intermediate issuer: %s", err.Error()))
	}
	intermediates[0] = intermediate

	c := &chain{
		root:          root,
		intermediates: intermediates,
	}
	ca.log.Printf("Generated issuance chain: %s", c)

	return c
}

func (ca *CAImpl) newCertificate(domains []string, ips []net.IP, key crypto.PublicKey, accountID, notBefore, notAfter string, extensions []pkix.Extension) (*core.Certificate, error) {
	if len(domains) == 0 && len(ips) == 0 {
		return nil, errors.New("must specify at least one domain name or IP address")
	}

	defaultChain := ca.chains[0].intermediates
	if len(defaultChain) == 0 || defaultChain[0].cert == nil {
		return nil, errors.New("cannot sign certificate - nil issuer")
	}
	issuer := defaultChain[0]

	certNotBefore := time.Now()
	var err error
	if notBefore != "" {
		certNotBefore, err = time.Parse(time.RFC3339, notBefore)
		if err != nil {
			return nil, fmt.Errorf("cannot parse Not Before date: %w", err)
		}
	}

	certNotAfter := certNotBefore.Add(time.Duration(ca.certValidityPeriod-1) * time.Second)
	maxNotAfter := time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	if certNotAfter.After(maxNotAfter) {
		certNotAfter = maxNotAfter
	}
	if notAfter != "" {
		certNotAfter, err = time.Parse(time.RFC3339, notAfter)
		if err != nil {
			return nil, fmt.Errorf("cannot parse Not After date: %w", err)
		}
	}

	serial := makeSerial()
	template := &x509.Certificate{
		DNSNames:     domains,
		IPAddresses:  ips,
		SerialNumber: serial,
		NotBefore:    certNotBefore,
		NotAfter:     certNotAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions:       extensions,
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

	issuers := make([][]*core.Certificate, len(ca.chains))
	for i := 0; i < len(ca.chains); i++ {
		issuerChain := make([]*core.Certificate, len(ca.chains[i].intermediates))
		for j, cert := range ca.chains[i].intermediates {
			issuerChain[j] = cert.cert
		}
		issuers[i] = issuerChain
	}

	hexSerial := hex.EncodeToString(cert.SerialNumber.Bytes())
	newCert := &core.Certificate{
		ID:           hexSerial,
		AccountID:    accountID,
		Cert:         cert,
		DER:          der,
		IssuerChains: issuers,
	}
	_, err = ca.db.AddCertificate(newCert)
	if err != nil {
		return nil, err
	}
	return newCert, nil
}

func New(log *log.Logger, db *db.MemoryStore, ocspResponderURL string, alternateRoots int, chainLength int, certificateValidityPeriod uint64) *CAImpl {
	ca := &CAImpl{
		log:                log,
		db:                 db,
		certValidityPeriod: defaultValidityPeriod,
	}

	if ocspResponderURL != "" {
		ca.ocspResponderURL = ocspResponderURL
		ca.log.Printf("Setting OCSP responder URL for issued certificates to %q", ca.ocspResponderURL)
	}

	intermediateSubject := pkix.Name{
		CommonName: intermediateCAPrefix + hex.EncodeToString(makeSerial().Bytes()[:3]),
	}
	intermediateKey, subjectKeyID, err := makeKey()
	if err != nil {
		panic(fmt.Sprintf("Error creating new intermediate private key: %s", err.Error()))
	}
	ca.chains = make([]*chain, 1+alternateRoots)
	for i := 0; i < len(ca.chains); i++ {
		ca.chains[i] = ca.newChain(intermediateKey, intermediateSubject, subjectKeyID, chainLength)
	}

	if certificateValidityPeriod != 0 && certificateValidityPeriod < 9223372038 {
		ca.certValidityPeriod = certificateValidityPeriod
	}

	ca.log.Printf("Using certificate validity period of %d seconds", ca.certValidityPeriod)

	return ca
}

var ocspMustStapleExt = pkix.Extension{
	Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24},
	Value: []byte{0x30, 0x03, 0x02, 0x01, 0x05},
}

// Returns whether the given extensions array contains an OCSP Must-Staple
// extension.
func extensionsContainsOCSPMustStaple(extensions []pkix.Extension) bool {
	for _, ext := range extensions {
		if ext.Id.Equal(ocspMustStapleExt.Id) && bytes.Equal(ext.Value, ocspMustStapleExt.Value) {
			return true
		}
	}
	return false
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

	// Build a list of approved extensions to include in the certificate
	var extensions []pkix.Extension
	if extensionsContainsOCSPMustStaple(order.ParsedCSR.Extensions) {
		// If the user requested an OCSP Must-Staple extension, use our
		// pre-baked one to ensure a reasonable value for Critical
		extensions = append(extensions, ocspMustStapleExt)
	}

	// issue a certificate for the csr
	csr := order.ParsedCSR
	cert, err := ca.newCertificate(csr.DNSNames, csr.IPAddresses, csr.PublicKey, order.AccountID, order.NotBefore, order.NotAfter, extensions)
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

// RecognizedSKID attempts to match the incoming Authority Key Idenfitier (AKID)
// bytes to the Subject Key Identifier (SKID) of an intermediate certificate. It
// returns an error if no match is found.
func (ca *CAImpl) RecognizedSKID(issuer []byte) error {
	if issuer == nil {
		return errors.New("issuer bytes must not be nil")
	}

	for _, chain := range ca.chains {
		for _, intermediate := range chain.intermediates {
			if bytes.Equal(intermediate.cert.Cert.SubjectKeyId, issuer) {
				return nil
			}
		}
	}

	return errors.New("no known issuer matches the provided Authority Key Identifier ")
}

func (ca *CAImpl) GetNumberOfRootCerts() int {
	return len(ca.chains)
}

func (ca *CAImpl) getChain(no int) *chain {
	if 0 <= no && no < len(ca.chains) {
		return ca.chains[no]
	}
	return nil
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

// GetIntermediateCert returns the first (closest the leaf) issuer certificate
// in the chain identified by `no`.
func (ca *CAImpl) GetIntermediateCert(no int) *core.Certificate {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}
	return chain.intermediates[0].cert
}

func (ca *CAImpl) GetIntermediateKey(no int) *rsa.PrivateKey {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}

	switch key := chain.intermediates[0].key.(type) {
	case *rsa.PrivateKey:
		return key
	}
	return nil
}
