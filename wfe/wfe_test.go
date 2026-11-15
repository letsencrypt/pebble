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
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
)

// newTestWFE builds a WebFrontEndImpl backed by a real MemoryStore, CA and VA.
func newTestWFE(t *testing.T) *WebFrontEndImpl {
	t.Helper()
	return newTestWFEWithCRL(t, nil)
}

// newTestWFEWithCRL is like newTestWFE, but with the given CRL configuration.
// A nil crl disables CRLs.
func newTestWFEWithCRL(t *testing.T, crl *ca.CRLConfig) *WebFrontEndImpl {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	memoryStore := db.NewMemoryStore()

	caImpl := ca.New(logger, memoryStore, "", "ecdsa", 0, 1, map[string]ca.Profile{"default": {}}, crl)
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

func TestProcessRevocationCRLVisibleAt(t *testing.T) {
	const maxDelay = 5
	for _, tc := range []struct {
		name string
		crl  *ca.CRLConfig
	}{
		{"CRLs disabled", nil},
		{"CRLs enabled", &ca.CRLConfig{BaseURL: "http://localhost:4003/", MaxDelay: maxDelay, Validity: time.Hour}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wfe := newTestWFEWithCRL(t, tc.crl)
			cert := issueTestCert(t, wfe)
			if prob := wfe.processRevocation(revocationBody(t, cert), allowRevocation); prob != nil {
				t.Fatalf("revocation failed: %+v", prob)
			}

			rc := wfe.db.GetRevokedCertificateBySerial(cert.Cert.SerialNumber)
			if rc == nil {
				t.Fatal("revoked certificate not found")
			}
			if tc.crl == nil {
				if !rc.CRLVisibleAt.Equal(rc.RevokedAt) {
					t.Errorf("CRLVisibleAt = %s, want RevokedAt %s", rc.CRLVisibleAt, rc.RevokedAt)
				}
				return
			}
			latest := rc.RevokedAt.Add(maxDelay * time.Second)
			if rc.CRLVisibleAt.Before(rc.RevokedAt) || rc.CRLVisibleAt.After(latest) {
				t.Errorf("CRLVisibleAt = %s, want within [%s, %s]", rc.CRLVisibleAt, rc.RevokedAt, latest)
			}
		})
	}
}

func TestCRLHandler(t *testing.T) {
	wfe := newTestWFEWithCRL(t, &ca.CRLConfig{BaseURL: "http://localhost:4003/", Validity: time.Hour})
	handler := wfe.CRLHandler()

	crlURL, err := url.Parse(wfe.ca.CRLURL())
	if err != nil {
		t.Fatalf("parsing CRL URL: %s", err)
	}

	fetch := func(t *testing.T) *x509.RevocationList {
		t.Helper()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, crlURL.Path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200", crlURL.Path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/pkix-crl" {
			t.Errorf("Content-Type = %q, want application/pkix-crl", ct)
		}
		crl, err := x509.ParseRevocationList(rec.Body.Bytes())
		if err != nil {
			t.Fatalf("parsing CRL: %s", err)
		}
		return crl
	}

	t.Run("empty CRL", func(t *testing.T) {
		if crl := fetch(t); len(crl.RevokedCertificateEntries) != 0 {
			t.Errorf("CRL has %d entries, want 0", len(crl.RevokedCertificateEntries))
		}
	})

	t.Run("revoked certificate", func(t *testing.T) {
		cert := issueTestCert(t, wfe)
		reason := uint(1)
		if prob := wfe.processRevocation(revocationBodyWithReason(t, cert, &reason), allowRevocation); prob != nil {
			t.Fatalf("revocation failed: %+v", prob)
		}
		crl := fetch(t)
		if len(crl.RevokedCertificateEntries) != 1 {
			t.Fatalf("CRL has %d entries, want 1", len(crl.RevokedCertificateEntries))
		}
		entry := crl.RevokedCertificateEntries[0]
		if entry.SerialNumber.Cmp(cert.Cert.SerialNumber) != 0 || entry.ReasonCode != 1 {
			t.Errorf("CRL entry = serial %s reason %d, want serial %s reason 1",
				entry.SerialNumber, entry.ReasonCode, cert.Cert.SerialNumber)
		}
	})

	t.Run("HEAD", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, crlURL.Path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("HEAD: status %d, want 200", rec.Code)
		}
	})

	t.Run("unknown path", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/crl/0000.crl", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET unknown path: status %d, want 404", rec.Code)
		}
	})

	t.Run("POST", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, crlURL.Path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST: status %d, want 405", rec.Code)
		}
	})
}
