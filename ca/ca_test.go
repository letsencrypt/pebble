package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
)

var ocspId asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
var ocspValue []byte = []byte{0x30, 0x03, 0x02, 0x01, 0x05}

func makeCa() *CAImpl {
	logger := log.New(os.Stdout, "Pebble ", log.LstdFlags)
	db := db.NewMemoryStore()
	return New(logger, db, "", 0, 1, 0)
}

func makeCertOrderWithExtensions(extensions []pkix.Extension) core.Order {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	csr := x509.CertificateRequest{
		DNSNames:    []string{"fake.domain"},
		IPAddresses: []net.IP{[]byte{192, 0, 2, 1}},
		PublicKey:   &privateKey.PublicKey,
		Extensions:  extensions,
	}
	return core.Order{
		ID:              "randomstring",
		AccountID:       "accountid",
		ParsedCSR:       &csr,
		BeganProcessing: true,
		Order: acme.Order{
			Status:      acme.StatusPending,
			Expires:     time.Now().AddDate(0, 0, 1).UTC().Format(time.RFC3339),
			Identifiers: []acme.Identifier{},
			NotBefore:   time.Now().UTC().Format(time.RFC3339),
			NotAfter:    time.Now().AddDate(30, 0, 0).UTC().Format(time.RFC3339),
		},
		ExpiresDate: time.Now().AddDate(0, 0, 1).UTC(),
	}
}

func getOCSPMustStapleExtension(cert *x509.Certificate) *pkix.Extension {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(ocspId) && bytes.Equal(ext.Value, ocspValue) {
			return &ext
		}
	}
	return nil
}

func TestNoExtensions(t *testing.T) {
	ca := makeCa()
	order := makeCertOrderWithExtensions([]pkix.Extension{})
	ca.CompleteOrder(&order)
	foundOCSPExtension := getOCSPMustStapleExtension(order.CertificateObject.Cert)
	if foundOCSPExtension != nil {
		t.Error("Expected no OCSP Must-Staple extension in complete cert, but found one")
	}
}

func TestSettingOCSPMustStapleExtension(t *testing.T) {
	// Base case
	ca := makeCa()
	order := makeCertOrderWithExtensions([]pkix.Extension{
		{
			Id:       ocspId,
			Critical: false,
			Value:    ocspValue,
		},
	})
	ca.CompleteOrder(&order)
	foundOCSPExtension := getOCSPMustStapleExtension(order.CertificateObject.Cert)
	if foundOCSPExtension == nil {
		t.Error("Expected OCSP Must-Staple extension in complete cert, but didn't find it")
	} else if foundOCSPExtension.Critical {
		t.Error("Expected foundOCSPExtension.Critical to be false, but it was true")
	}

	// Test w/ improperly set Critical value
	ca = makeCa()
	order = makeCertOrderWithExtensions([]pkix.Extension{
		{
			Id:       ocspId,
			Critical: true,
			Value:    ocspValue,
		},
	})
	ca.CompleteOrder(&order)
	foundOCSPExtension = getOCSPMustStapleExtension(order.CertificateObject.Cert)
	if foundOCSPExtension == nil {
		t.Error("Expected OCSP Must-Staple extension in complete cert, but didn't find it")
	} else if foundOCSPExtension.Critical {
		t.Error("Expected foundOCSPExtension.Critical to be false, but it was true")
	}

	// Test w/ duplicate extensions
	ca = makeCa()
	order = makeCertOrderWithExtensions([]pkix.Extension{
		{
			Id:       ocspId,
			Critical: true,
			Value:    ocspValue,
		},
		{
			Id:       ocspId,
			Critical: true,
			Value:    ocspValue,
		},
	})
	ca.CompleteOrder(&order)
	numOCSPMustStapleExtensions := 0
	for _, ext := range order.CertificateObject.Cert.Extensions {
		if ext.Id.Equal(ocspId) && bytes.Equal(ext.Value, ocspValue) {
			numOCSPMustStapleExtensions += 1
		}
	}
	if numOCSPMustStapleExtensions != 1 {
		t.Errorf("Expected exactly 1 OCSP Must-Staple extension, found %d", numOCSPMustStapleExtensions)
	}
}
