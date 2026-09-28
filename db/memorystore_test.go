package db

import (
	"testing"
	"time"

	"github.com/letsencrypt/pebble/v2/core"
)

func TestRevokeCertificateTwice(t *testing.T) {
	m := NewMemoryStore()
	cert := &core.Certificate{ID: "01"}

	reason := uint(1)
	first := &core.RevokedCertificate{
		Certificate: cert,
		RevokedAt:   time.Now(),
		Reason:      &reason,
	}
	if !m.RevokeCertificate(first) {
		t.Fatal("first RevokeCertificate returned false, want true")
	}

	second := &core.RevokedCertificate{
		Certificate: cert,
		RevokedAt:   first.RevokedAt.Add(time.Hour),
	}
	if m.RevokeCertificate(second) {
		t.Fatal("second RevokeCertificate returned true, want false")
	}

	if got := m.revokedCertificatesByID[cert.ID]; got != first {
		t.Errorf("stored entry = %+v, want the first entry %+v", got, first)
	}
}
