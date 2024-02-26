package ca

import (
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

func TestOCSPMustStaple(t *testing.T) {
	logger := log.New(os.Stdout, "Pebble ", log.LstdFlags)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	db := db.NewMemoryStore()
	ca := New(logger, db, "", 0, 1, 0)
	csr := x509.CertificateRequest{
		DNSNames:    []string{"test.org"},
		IPAddresses: []net.IP{[]byte{10, 255, 0, 0}},
		PublicKey:   &privateKey.PublicKey,
		Extensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24},
				Critical: false,
				Value:    []byte{0x30, 0x03, 0x02, 0x01, 0x05},
			},
		},
	}
	var uniquenames []acme.Identifier
	uniquenames = append(uniquenames, acme.Identifier{Value: "13.12.13.12", Type: acme.IdentifierIP})
	order := &core.Order{
		ID:              "randomstring",
		AccountID:       "accountid",
		ParsedCSR:       &csr,
		BeganProcessing: true,
		Order: acme.Order{
			Status:      acme.StatusPending,
			Expires:     time.Now().AddDate(0, 0, 1).UTC().Format(time.RFC3339),
			Identifiers: uniquenames,
			NotBefore:   time.Now().UTC().Format(time.RFC3339),
			NotAfter:    time.Now().AddDate(30, 0, 0).UTC().Format(time.RFC3339),
		},
		ExpiresDate: time.Now().AddDate(0, 0, 1).UTC(),
	}

	ca.CompleteOrder(order)
	log.Printf("cert: %+v", order.CertificateObject.Cert)
}
