package ca

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"log"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
)

// reasonCodeOID identifies the CRL entry reasonCode extension. Go reports an
// absent reasonCode as 0, so tests look for the raw extension instead.
var reasonCodeOID = asn1.ObjectIdentifier{2, 5, 29, 21}

func makeCRLCa(t *testing.T, crl *CRLConfig, alternateRoots int) *CAImpl {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	return New(logger, db.NewMemoryStore(), "", "ecdsa", alternateRoots, 1, map[string]Profile{"default": {}}, crl)
}

func testCRLConfig() *CRLConfig {
	return &CRLConfig{
		BaseURL:  "http://localhost:4003/",
		MaxDelay: 0,
		Validity: 7 * 24 * time.Hour,
	}
}

func issueCert(t *testing.T, ca *CAImpl) *core.Certificate {
	t.Helper()
	order := makeCertOrderWithExtensions(nil)
	ca.CompleteOrder(&order)
	if order.CertificateObject == nil {
		t.Fatal("CA did not issue a certificate")
	}
	return order.CertificateObject
}

func revoke(t *testing.T, ca *CAImpl, cert *core.Certificate, reason *uint, visibleAt time.Time) {
	t.Helper()
	if !ca.db.RevokeCertificate(&core.RevokedCertificate{
		Certificate:  cert,
		RevokedAt:    time.Now(),
		Reason:       reason,
		CRLVisibleAt: visibleAt,
	}) {
		t.Fatalf("certificate %s was already revoked", cert.ID)
	}
}

func getCRL(t *testing.T, ca *CAImpl) *x509.RevocationList {
	t.Helper()
	der, err := ca.GetCRL()
	if err != nil {
		t.Fatalf("GetCRL: %s", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parsing CRL: %s", err)
	}
	return crl
}

func findEntry(crl *x509.RevocationList, cert *core.Certificate) *x509.RevocationListEntry {
	for i, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.Cert.SerialNumber) == 0 {
			return &crl.RevokedCertificateEntries[i]
		}
	}
	return nil
}

func TestCRLDisabled(t *testing.T) {
	ca := makeCRLCa(t, nil, 0)

	if got := ca.CRLURL(); got != "" {
		t.Errorf("CRLURL() = %q, want empty", got)
	}
	now := time.Now()
	if got := ca.CRLVisibleAt(now); !got.Equal(now) {
		t.Errorf("CRLVisibleAt(%s) = %s, want the same time", now, got)
	}
	if cert := issueCert(t, ca); len(cert.Cert.CRLDistributionPoints) != 0 {
		t.Errorf("certificate has CRLDP %v, want none", cert.Cert.CRLDistributionPoints)
	}
	if _, err := ca.GetCRL(); err == nil {
		t.Error("GetCRL() succeeded with CRLs disabled, want an error")
	}
}

func TestCRLURLAndCRLDP(t *testing.T) {
	ca := makeCRLCa(t, testCRLConfig(), 0)

	skid := ca.chains[0].intermediates[0].cert.Cert.SubjectKeyId
	want := "http://localhost:4003/crl/" + hex.EncodeToString(skid) + ".crl"
	if got := ca.CRLURL(); got != want {
		t.Errorf("CRLURL() = %q, want %q", got, want)
	}

	cert := issueCert(t, ca)
	if !slices.Equal(cert.Cert.CRLDistributionPoints, []string{want}) {
		t.Errorf("certificate CRLDP = %v, want [%s]", cert.Cert.CRLDistributionPoints, want)
	}
}

func TestCACertsHaveCRLSign(t *testing.T) {
	ca := makeCRLCa(t, nil, 1)
	for i, c := range ca.chains {
		for _, iss := range append(slices.Clone(c.intermediates), c.root) {
			if iss.cert.Cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
				t.Errorf("chain %d: %s lacks KeyUsageCRLSign", i, iss.cert.Cert.Subject)
			}
		}
	}
}

func TestCRLVisibleAtDelay(t *testing.T) {
	cfg := testCRLConfig()
	cfg.MaxDelay = 3
	ca := makeCRLCa(t, cfg, 0)

	revokedAt := time.Now()
	for range 100 {
		got := ca.CRLVisibleAt(revokedAt)
		if got.Before(revokedAt) || got.After(revokedAt.Add(3*time.Second)) {
			t.Fatalf("CRLVisibleAt = %s, want within [%s, %s]", got, revokedAt, revokedAt.Add(3*time.Second))
		}
	}

	ca = makeCRLCa(t, testCRLConfig(), 0)
	if got := ca.CRLVisibleAt(revokedAt); !got.Equal(revokedAt) {
		t.Errorf("CRLVisibleAt with MaxDelay 0 = %s, want %s", got, revokedAt)
	}
}

func TestCRLEntryVisibility(t *testing.T) {
	ca := makeCRLCa(t, testCRLConfig(), 0)

	future := issueCert(t, ca)
	past := issueCert(t, ca)
	revoke(t, ca, future, nil, time.Now().Add(time.Hour))
	revoke(t, ca, past, nil, time.Now().Add(-time.Second))

	crl := getCRL(t, ca)
	if findEntry(crl, future) != nil {
		t.Error("entry with CRLVisibleAt in the future is on the CRL")
	}
	if findEntry(crl, past) == nil {
		t.Error("entry with CRLVisibleAt in the past is missing from the CRL")
	}
}

func TestCRLImmediateWithNoDelay(t *testing.T) {
	ca := makeCRLCa(t, testCRLConfig(), 0)
	cert := issueCert(t, ca)
	revoke(t, ca, cert, nil, ca.CRLVisibleAt(time.Now()))

	if findEntry(getCRL(t, ca), cert) == nil {
		t.Error("revoked certificate missing from CRL with MaxDelay 0")
	}
}

func TestCRLKeepsExpiredCerts(t *testing.T) {
	ca := makeCRLCa(t, testCRLConfig(), 0)
	notBefore := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	notAfter := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	order := makeCertOrderWithExtensions(nil)
	cert, err := ca.newCertificate(order.ParsedCSR.DNSNames, nil, order.ParsedCSR.PublicKey, "acct", notBefore, notAfter, "default", nil)
	if err != nil {
		t.Fatalf("issuing expired certificate: %s", err)
	}
	if !cert.Cert.NotAfter.Before(time.Now()) {
		t.Fatalf("certificate NotAfter %s is not in the past", cert.Cert.NotAfter)
	}
	revoke(t, ca, cert, nil, time.Now().Add(-time.Second))

	if findEntry(getCRL(t, ca), cert) == nil {
		t.Error("expired revoked certificate missing from CRL")
	}
}

func TestCRLReasonCodes(t *testing.T) {
	ca := makeCRLCa(t, testCRLConfig(), 0)

	zero, keyCompromise := uint(0), uint(1)
	noReason := issueCert(t, ca)
	unspecified := issueCert(t, ca)
	compromised := issueCert(t, ca)
	visible := time.Now().Add(-time.Second)
	revoke(t, ca, noReason, nil, visible)
	revoke(t, ca, unspecified, &zero, visible)
	revoke(t, ca, compromised, &keyCompromise, visible)

	crl := getCRL(t, ca)
	for name, cert := range map[string]*core.Certificate{"nil reason": noReason, "reason 0": unspecified} {
		entry := findEntry(crl, cert)
		if entry == nil {
			t.Fatalf("%s: entry missing from CRL", name)
		}
		for _, ext := range entry.Extensions {
			if ext.Id.Equal(reasonCodeOID) {
				t.Errorf("%s: entry has a reasonCode extension, want none", name)
			}
		}
	}

	entry := findEntry(crl, compromised)
	if entry == nil {
		t.Fatal("keyCompromise entry missing from CRL")
	}
	if entry.ReasonCode != 1 {
		t.Errorf("keyCompromise entry ReasonCode = %d, want 1", entry.ReasonCode)
	}
}

func TestCRLNumberAndValidity(t *testing.T) {
	cfg := testCRLConfig()
	cfg.Validity = 36 * time.Hour
	ca := makeCRLCa(t, cfg, 0)

	first := getCRL(t, ca)
	second := getCRL(t, ca)
	if second.Number.Cmp(first.Number) <= 0 {
		t.Errorf("CRL number did not increase: %s then %s", first.Number, second.Number)
	}
	if got := first.NextUpdate.Sub(first.ThisUpdate); got != cfg.Validity {
		t.Errorf("nextUpdate - thisUpdate = %s, want %s", got, cfg.Validity)
	}
	if len(first.RevokedCertificateEntries) != 0 {
		t.Errorf("CRL with nothing revoked has %d entries, want 0", len(first.RevokedCertificateEntries))
	}
}

func TestCRLConcurrent(t *testing.T) {
	ca := makeCRLCa(t, testCRLConfig(), 0)
	certs := make([]*core.Certificate, 20)
	for i := range certs {
		certs[i] = issueCert(t, ca)
	}

	const workers = 20
	ders := make([][]byte, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Go(func() {
			ca.db.RevokeCertificate(&core.RevokedCertificate{
				Certificate:  certs[i],
				RevokedAt:    time.Now(),
				CRLVisibleAt: time.Now(),
			})
			der, err := ca.GetCRL()
			if err != nil {
				t.Errorf("GetCRL: %s", err)
				return
			}
			ders[i] = der
		})
	}
	wg.Wait()

	crls := make([]*x509.RevocationList, 0, workers)
	for _, der := range ders {
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatalf("parsing CRL: %s", err)
		}
		crls = append(crls, crl)
	}
	slices.SortFunc(crls, func(a, b *x509.RevocationList) int { return a.Number.Cmp(b.Number) })

	for i := 1; i < len(crls); i++ {
		prev, cur := crls[i-1], crls[i]
		if cur.Number.Cmp(prev.Number) == 0 {
			t.Errorf("duplicate CRL number %s", cur.Number)
		}
		if cur.ThisUpdate.Before(prev.ThisUpdate) {
			t.Errorf("CRL %s has thisUpdate %s before CRL %s's %s", cur.Number, cur.ThisUpdate, prev.Number, prev.ThisUpdate)
		}
		if len(cur.RevokedCertificateEntries) < len(prev.RevokedCertificateEntries) {
			t.Errorf("CRL %s has fewer entries (%d) than CRL %s (%d)", cur.Number,
				len(cur.RevokedCertificateEntries), prev.Number, len(prev.RevokedCertificateEntries))
		}
	}
}

func TestCRLSignatureVerifiesAgainstAllChains(t *testing.T) {
	ca := makeCRLCa(t, testCRLConfig(), 2)
	crl := getCRL(t, ca)
	for i, c := range ca.chains {
		if err := crl.CheckSignatureFrom(c.intermediates[0].cert.Cert); err != nil {
			t.Errorf("CRL signature does not verify against chain %d's intermediate: %s", i, err)
		}
	}
}
