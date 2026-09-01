package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
)

var (
	ocspID    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	ocspValue = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
)

func makeCa() *CAImpl {
	logger := log.New(os.Stdout, "Pebble ", log.LstdFlags)
	db := db.NewMemoryStore()
	return New(
		logger,
		db,
		"",
		"ecdsa",
		0,
		1,
		map[string]Profile{"default": {}},
		WithSubjectKeyIdentifierHash(SubjectKeyIdentifierHashSHA256),
	)
}

func testMakeSubjectKeyID(t *testing.T, hash SubjectKeyIdentifierHash, expected string) {
	t.Helper()
	publicKeyBytes, err := hex.DecodeString(
		"047f7f35a79794c950060b8029fc8f363a28f11159692d9d34e6ac948190434735" +
			"f833b1a66652dc514337aff7f5c9c75d670c019d95a5d639b72744c64a9128bb",
	)
	if err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKeyBytes)
	if x == nil || y == nil {
		t.Fatal("failed to parse RFC 7093 public key")
	}

	got, err := makeSubjectKeyID(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, hash)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(expected)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected subject key identifier: got %x, want %x", got, want)
	}
}

func TestMakeSubjectKeyIDSHA1(t *testing.T) {
	if fips140.Enforced() {
		t.Skip("SHA-1 is unavailable when FIPS enforcement is enabled")
	}
	testMakeSubjectKeyID(t, SubjectKeyIdentifierHashSHA1, "6fef9162c0a3f2e7608956d41c37da0c8e87f0ae")
}

func TestMakeSubjectKeyIDSHA256(t *testing.T) {
	testMakeSubjectKeyID(t, SubjectKeyIdentifierHashSHA256, "bf37b3e5808fd46d54b28e846311bcce1cad2e1a")
}

func TestMakeSubjectKeyIDRejectsUnknownHash(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := makeSubjectKeyID(key.Public(), SubjectKeyIdentifierHash("unknown")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestWithSubjectKeyIdentifierHash(t *testing.T) {
	ca := makeCa()
	if ca.subjectKeyIdentifierHash != SubjectKeyIdentifierHashSHA256 {
		t.Fatalf("unexpected hash: got %q, want %q", ca.subjectKeyIdentifierHash, SubjectKeyIdentifierHashSHA256)
	}
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
			Profile:     "default",
			NotBefore:   time.Now().UTC().Format(time.RFC3339),
			NotAfter:    time.Now().AddDate(30, 0, 0).UTC().Format(time.RFC3339),
		},
		ExpiresDate: time.Now().AddDate(0, 0, 1).UTC(),
	}
}

func getOCSPMustStapleExtension(cert *x509.Certificate) *pkix.Extension {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(ocspID) && bytes.Equal(ext.Value, ocspValue) {
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
			Id:       ocspID,
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
			Id:       ocspID,
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
			Id:       ocspID,
			Critical: true,
			Value:    ocspValue,
		},
		{
			Id:       ocspID,
			Critical: true,
			Value:    ocspValue,
		},
	})
	ca.CompleteOrder(&order)
	numOCSPMustStapleExtensions := 0
	for _, ext := range order.CertificateObject.Cert.Extensions {
		if ext.Id.Equal(ocspID) && bytes.Equal(ext.Value, ocspValue) {
			numOCSPMustStapleExtensions++
		}
	}
	if numOCSPMustStapleExtensions != 1 {
		t.Errorf("Expected exactly 1 OCSP Must-Staple extension, found %d", numOCSPMustStapleExtensions)
	}
}
