package va

import (
	"crypto/x509"
	"encoding/base64"
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

const testpem1 = `
-----BEGIN CERTIFICATE REQUEST-----
MIIBDzCBwgIBADAAMCowBQYDK2VwAyEAAJhHmOIxin7dZvKd6aiZGCNrl2ngSbR1
1Ei727ydOEaggY4wFAYEZ4EMKjEMBAosNiTQxXU35ZAqMBoGBGeBDCkxEgQQYpVw
QRzcyq72eWGTw8flMjBaBgkqhkiG9w0BCQ4xTTBLMEkGA1UdEQRCMECCPmFjbWVw
Z2hjZ2dmaDV4bGc2a282dGtlemRhcnd4ZjNqNGJlM2k1b3VqYzU1eHBlNWhiZGph
dXFkLm9uaW9uMAUGAytlcANBACfTi2BHuRhWP+UHJ75zz/Vh2HNj7A97Jeq/JDyN
EMSC/YZWhP+vFEdveAzWgi3IBDNCkJpp09HbDhyJNgfNvw8=
-----END CERTIFICATE REQUEST-----`
const testnonce1 = "629570411cdccaaef6796193c3c7e532"
const testpem2 = `
-----BEGIN CERTIFICATE REQUEST-----
MIIBZTCCARcCAQAwSTFHMEUGA1UEAww+cDRlcnlzYWdmbmFqNjdsdzM2bnhhNTJw
NHpsNmdnYm5qbXM1YjVvdWN1M3R5cW5mbGpiZHhwYWQub25pb24wKjAFBgMrZXAD
IQB/CRxIBitAn31235twd0/mV+MYLUsl0PXUFTc8QaVaQqCBmjAaBgRngQwqMRIE
EB+SJmsKEym4YvIVmE0TvkUwIAYEZ4EMKTEYBBZBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBMFoGCSqGSIb3DQEJDjFNMEswSQYDVR0RBEIwQII+cDRlcnlzYWdmbmFqNjds
dzM2bnhhNTJwNHpsNmdnYm5qbXM1YjVvdWN1M3R5cW5mbGpiZHhwYWQub25pb24w
BQYDK2VwA0EAy3OwkUqOwn0f4RJYQubT6bT7XxSblfoVMf/GU8KZWCgrINCPs+II
I7owLXMkZl2ubqH2RnDGELbYTmNu8sPVBQ==
-----END CERTIFICATE REQUEST-----
`
const testpem3 = `
-----BEGIN CERTIFICATE REQUEST-----
MIIBZTCCARcCAQAwSTFHMEUGA1UEAww+cWR6anFtajM1bnB0eTQ0a3BxNXR2bzZh
dTJudWFuZ2M1Mnlpam1kNnNoZWJmMnFiZnpyajdoeWQub25pb24wKjAFBgMrZXAD
IQCA8pgxO+tfPHOKfDs6u8Cmm0A0wu6whLB+kcgS6gEuYqCBmjAaBgRngQwqMRIE
ELwrCMgcgOwdZoJyvCoSQCwwIAYEZ4EMKTEYBBZBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBMFoGCSqGSIb3DQEJDjFNMEswSQYDVR0RBEIwQII+cWR6anFtajM1bnB0eTQ0
a3BxNXR2bzZhdTJudWFuZ2M1Mnlpam1kNnNoZWJmMnFiZnpyajdoeWQub25pb24w
BQYDK2VwA0EAigobub8B+wWRbnVTFe6rh67wQ9uHJ12860nCdwUE2NPCBdetjoHj
QQC2tybGFFKOgOKEG7oeyUh9aRpt1SLXAw==
-----END CERTIFICATE REQUEST-----
`

func TestOnionCSRPasrse(t *testing.T) {

	// testonionaddress := "acmepghcggfh5xlg6ko6tkezdarwxf3j4be3i5oujc55xpe5hbdjauqd.onion"
	decodedpem, rest := pem.Decode([]byte(testpem3))
	if decodedpem == nil {
		panic(rest)
	}
	dercert, err := base64.RawURLEncoding.DecodeString("MIIBejCCASwCAQAwSTFHMEUGA1UEAww-YWNtZXBnaGNnZ2ZoNXhsZzZrbzZ0a2V6ZGFyd3hmM2o0YmUzaTVvdWpjNTV4cGU1aGJkamF1cWQub25pb24wKjAFBgMrZXADIQAAmEeY4jGKft1m8p3pqJkYI2uXaeBJtHXUSLvbvJ04RqCBrzAaBgRngQwqMRIEEOQBIW4cN20UtlQl19r_-XAwNQYEZ4EMKTEtBCtoNnZoX1lCbF9nQWtHdDBja203V2J2Q1Q4Z3NKNFQ4WURqejkwazdxQjZBMFoGCSqGSIb3DQEJDjFNMEswSQYDVR0RBEIwQII-YWNtZXBnaGNnZ2ZoNXhsZzZrbzZ0a2V6ZGFyd3hmM2o0YmUzaTVvdWpjNTV4cGU1aGJkamF1cWQub25pb24wBQYDK2VwA0EAc8dKAVeF2sVbkCsPcO0YPDVeY1d1OSvFOYIRIL-akCHPiFGu0y02NW5aH1oweLG4gzl5UlFtVEPInE_Bciw-Bw")
	onioncsr, err := x509.ParseCertificateRequest(dercert)
	if err != nil {
		panic(err)
	}
	err = onioncsr.CheckSignature()
	if err != nil {
		panic(err)
	}
	print(err)
	csrNonce, err1 := ExtractNonce(onioncsr)
	print(csrNonce)
	if err1 != nil {
		panic(err1)
	}
}
