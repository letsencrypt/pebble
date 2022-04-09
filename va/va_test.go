package va

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log"
	"os"
	"sync"
	"testing"

	"github.com/letsencrypt/pebble/acme"
	"github.com/letsencrypt/pebble/core"
	"github.com/letsencrypt/pebble/db"
)

func TestAuthzRace(t *testing.T) {
	// Exercises a specific (fixed) race condition:
	// WARNING: DATA RACE
	// Read at 0x00c00040cde8 by goroutine 55:
	//  github.com/letsencrypt/pebble/db.(*MemoryStore).FindValidAuthorization()
	//      /tank/tank/src/pebble/db/memorystore.go:263 +0x18e
	//  github.com/letsencrypt/pebble/wfe.(*WebFrontEndImpl).makeAuthorizations()
	//      /tank/tank/src/pebble/wfe/wfe.go:1503 +0x2cf
	// ...
	// Previous write at 0x00c00040cde8 by goroutine 76:
	//  github.com/letsencrypt/pebble/va.VAImpl.setAuthzValid()
	//      /tank/tank/src/pebble/va/va.go:196 +0x2a6
	//  github.com/letsencrypt/pebble/va.VAImpl.process()
	//      /tank/tank/src/pebble/va/va.go:264 +0x83b

	// VAImpl.setAuthzInvalid updates authz.Status
	// MemoryStore.FindValidAuthorization searches and tests authz.Status

	// This whole test can be removed if/when the MemoryStore becomes 100% by value
	ms := db.NewMemoryStore()
	va := New(log.New(os.Stdout, "Pebble/TestRace", log.LstdFlags), 14000, 15000, false, "")

	authz := &core.Authorization{
		ID: "auth-id",
	}

	_, err := ms.AddAuthorization(authz)
	if err != nil {
		panic("")
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		ms.FindValidAuthorization("", acme.Identifier{})
		wg.Done()
	}()
	va.setAuthzInvalid(authz, &core.Challenge{}, nil)
	wg.Wait()
}

func TestOnionCSRPasrse(t *testing.T) {

	const testpem = `
-----BEGIN CERTIFICATE REQUEST-----
MIIBDzCBwgIBADAAMCowBQYDK2VwAyEAAJhHmOIxin7dZvKd6aiZGCNrl2ngSbR1
1Ei727ydOEaggY4wFAYEZ4EMKjEMBAosNiTQxXU35ZAqMBoGBGeBDCkxEgQQYpVw
QRzcyq72eWGTw8flMjBaBgkqhkiG9w0BCQ4xTTBLMEkGA1UdEQRCMECCPmFjbWVw
Z2hjZ2dmaDV4bGc2a282dGtlemRhcnd4ZjNqNGJlM2k1b3VqYzU1eHBlNWhiZGph
dXFkLm9uaW9uMAUGAytlcANBACfTi2BHuRhWP+UHJ75zz/Vh2HNj7A97Jeq/JDyN
EMSC/YZWhP+vFEdveAzWgi3IBDNCkJpp09HbDhyJNgfNvw8=
-----END CERTIFICATE REQUEST-----`
	Noncehex, err := hex.DecodeString("629570411cdccaaef6796193c3c7e532")
	if err != nil {
		panic("failed to parse hex")
	}
	// testonionaddress := "acmepghcggfh5xlg6ko6tkezdarwxf3j4be3i5oujc55xpe5hbdjauqd.onion"
	decodedpem, rest := pem.Decode([]byte(testpem))
	if decodedpem == nil {
		panic(rest)
	}
	onioncsr, err := x509.ParseCertificateRequest(decodedpem.Bytes)
	if err != nil {
		panic(err)
	}
	testresult := OnionNonceCheck(onioncsr, Noncehex)
	if testresult != nil {
		panic(testresult)
	}
}
