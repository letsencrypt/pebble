package wfe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"testing"

	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
)

// newTestWFE builds a WebFrontEndImpl backed by a real MemoryStore, CA and VA.
func newTestWFE(t *testing.T) *WebFrontEndImpl {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	memoryStore := db.NewMemoryStore()

	caImpl := ca.New(logger, memoryStore, "", "ecdsa", 0, 1, map[string]ca.Profile{"default": {}}, nil)
	vaImpl := va.New(logger, 0, 0, false, "", memoryStore)

	wfeImpl := New(logger, memoryStore, vaImpl, caImpl, nil, false, false, 0, 0)
	return &wfeImpl
}

// issueTestCert issues a leaf certificate through the WFE's CA and returns it.
func issueTestCert(t *testing.T, wfe *WebFrontEndImpl) *core.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %s", err)
	}

	order := &core.Order{
		Order: acme.Order{Profile: "default"},
		ParsedCSR: &x509.CertificateRequest{
			DNSNames:  []string{"example.com"},
			PublicKey: key.Public(),
		},
		BeganProcessing: true,
	}

	wfe.ca.CompleteOrder(order)
	if order.CertificateObject == nil {
		t.Fatal("CA did not issue a certificate")
	}

	return order.CertificateObject
}

// revocationBody returns a revocation request JSON body for cert.
func revocationBody(t *testing.T, cert *core.Certificate) []byte {
	t.Helper()
	return revocationBodyWithReason(t, cert, nil)
}

// revocationBodyWithReason returns a revocation request JSON body for cert
// with the given reason code, or no reason if reason is nil.
func revocationBodyWithReason(t *testing.T, cert *core.Certificate, reason *uint) []byte {
	t.Helper()

	body, err := json.Marshal(struct {
		Certificate string `json:"certificate"`
		Reason      *uint  `json:"reason,omitempty"`
	}{
		Certificate: base64.RawURLEncoding.EncodeToString(cert.DER),
		Reason:      reason,
	})
	if err != nil {
		t.Fatalf("marshaling revocation body: %s", err)
	}

	return body
}

func TestProcessRevocationConcurrent(t *testing.T) {
	wfe := newTestWFE(t)
	cert := issueTestCert(t, wfe)
	body := revocationBody(t, cert)

	const workers = 10
	var authWg sync.WaitGroup
	authWg.Add(workers)

	// This callback is called right before the actual attempt to mark the
	// certificate revoked, which allows us to synchronize the workers and test
	// what happens when revocations race.
	var authorize authorizedToRevokeCert = func(*core.Certificate) *acme.ProblemDetails {
		authWg.Done()
		authWg.Wait()
		return nil
	}

	results := make([]*acme.ProblemDetails, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Go(func() {
			results[i] = wfe.processRevocation(body, authorize)
		})
	}
	wg.Wait()

	alreadyRevokedType := acme.AlreadyRevokedProblem("").Type
	var successes int
	for _, prob := range results {
		switch {
		case prob == nil:
			successes++
		case prob.Type != alreadyRevokedType:
			t.Errorf("unexpected problem: %+v", prob)
		}
	}
	if successes != 1 {
		t.Errorf("got %d successful revocations, want exactly 1", successes)
	}
}

func allowRevocation(*core.Certificate) *acme.ProblemDetails { return nil }

func TestProcessRevocationReasons(t *testing.T) {
	badReasonType := acme.BadRevocationReasonProblem("").Type
	for reason := range uint(12) {
		t.Run(fmt.Sprintf("reason %d", reason), func(t *testing.T) {
			wfe := newTestWFE(t)
			cert := issueTestCert(t, wfe)
			prob := wfe.processRevocation(revocationBodyWithReason(t, cert, &reason), allowRevocation)

			switch reason {
			case 0, 1, 3, 4, 5, 9:
				if prob != nil {
					t.Errorf("revocation with reason %d failed: %+v", reason, prob)
				}
			default:
				if prob == nil || prob.Type != badReasonType {
					t.Errorf("revocation with reason %d: got %+v, want %s", reason, prob, badReasonType)
				}
			}
		})
	}
}
