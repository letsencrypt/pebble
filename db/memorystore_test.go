package db

import (
	"strconv"
	"sync"
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

func TestGetRevokedCertificates(t *testing.T) {
	m := NewMemoryStore()
	if got := m.GetRevokedCertificates(); len(got) != 0 {
		t.Fatalf("GetRevokedCertificates() on empty store = %v, want empty", got)
	}

	for _, id := range []string{"01", "02"} {
		m.RevokeCertificate(&core.RevokedCertificate{
			Certificate: &core.Certificate{ID: id},
			RevokedAt:   time.Now(),
		})
	}

	got := m.GetRevokedCertificates()
	if len(got) != 2 {
		t.Fatalf("GetRevokedCertificates() returned %d entries, want 2", len(got))
	}

	// The result is a copy: changing it must not affect the store.
	got[0] = nil
	for _, rc := range m.GetRevokedCertificates() {
		if rc == nil {
			t.Fatal("modifying the returned slice changed the store")
		}
	}
}

func TestGetRevokedCertificatesConcurrent(t *testing.T) {
	m := NewMemoryStore()
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			m.RevokeCertificate(&core.RevokedCertificate{
				Certificate: &core.Certificate{ID: strconv.Itoa(i)},
				RevokedAt:   time.Now(),
			})
		})
		wg.Go(func() {
			_ = m.GetRevokedCertificates()
		})
	}
	wg.Wait()

	if got := len(m.GetRevokedCertificates()); got != 20 {
		t.Errorf("GetRevokedCertificates() returned %d entries, want 20", got)
	}
}
