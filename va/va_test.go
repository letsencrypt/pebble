package va

import (
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
)

func TestAuthzRace(_ *testing.T) {
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
	va := New(log.New(os.Stdout, "Pebble/TestRace", log.LstdFlags), 14000, 15000, false, "", ms)

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

func TestValidateDNSPersist01(t *testing.T) {
	t.Parallel()

	const (
		domain     = "example.com"
		txtName    = "_validation-persist.example.com"
		accountURL = "https://ca.example/acct/123"
	)

	testCases := []struct {
		name               string
		challIssuerNames   []string
		challTXTRecords    []string
		challWildcard      bool
		expectErr          bool
		expectHTTPStatus   int
		expectDetailSubstr string
	}{
		// Success test cases:
		{
			name:             "matching malformed and matching valid record succeeds",
			challIssuerNames: []string{"authority.example"},
			challTXTRecords: []string{
				"authority.example;accounturi=https://ca.example/acct/123;accounturi=https://ca.example/acct/456",
				"authority.example;accounturi=https://ca.example/acct/123",
			},
		},
		{
			name:             "matching unauthorized and matching valid record succeeds",
			challIssuerNames: []string{"authority.example"},
			challTXTRecords: []string{
				"authority.example;accounturi=https://ca.example/acct/999",
				"authority.example;accounturi=https://ca.example/acct/123",
			},
		},
		{
			name:             "unknown tag with empty value succeeds",
			challIssuerNames: []string{"authority.example"},
			challTXTRecords: []string{
				"authority.example;accounturi=https://ca.example/acct/123;foo=",
			},
		},
		{
			name:             "unknown tags are ignored",
			challIssuerNames: []string{"authority.example"},
			challTXTRecords: []string{
				"authority.example;accounturi=https://ca.example/acct/123;bad tag=value;\nweird=\\x01337",
			},
		},
		{
			name:             "all known fields with heavy whitespace succeeds",
			challIssuerNames: []string{"authority.example"},
			challTXTRecords: []string{
				"   authority.example   ;   accounturi   =   https://ca.example/acct/123   ;   policy   =   wildcard   ;   persistUntil   =   4102444800   ",
			},
		},
		{
			name:             "wildcard accepts case-insensitive policy value",
			challIssuerNames: []string{"authority.example"},
			challTXTRecords:  []string{"authority.example;accounturi=https://ca.example/acct/123;policy=wIlDcArD"},
			challWildcard:    true,
		},
		{
			name:             "wildcard accepts case-insensitive policy tag",
			challIssuerNames: []string{"authority.example"},
			challTXTRecords:  []string{"authority.example;accounturi=https://ca.example/acct/123;pOlIcY=wildcard"},
			challWildcard:    true,
		},
		// Failure test cases:
		{
			name:               "only matching malformed record returns malformed",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/123;accounturi=https://ca.example/acct/456"},
			expectErr:          true,
			expectHTTPStatus:   400,
			expectDetailSubstr: `duplicate parameter`,
		},
		{
			name:               "no txt records found returns unauthorized",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{},
			expectErr:          true,
			expectHTTPStatus:   403,
			expectDetailSubstr: `No TXT records found for DNS-PERSIST-01 challenge`,
		},
		{
			name:               "only matching unauthorized record returns unauthorized",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/999"},
			expectErr:          true,
			expectHTTPStatus:   403,
			expectDetailSubstr: `accounturi mismatch`,
		},
		{
			name:               "non-matching malformed record is ignored",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"other.example;accounturi=https://ca.example/acct/123;accounturi=https://ca.example/acct/456"},
			expectErr:          true,
			expectHTTPStatus:   403,
			expectDetailSubstr: `No valid TXT record found`,
		},
		{
			name:               "missing equals is malformed",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/123;invalidparam"},
			expectErr:          true,
			expectHTTPStatus:   400,
			expectDetailSubstr: `malformed parameter "invalidparam" should be tag=value pair`,
		},
		{
			name:               "empty tag is malformed",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/123;=abc"},
			expectErr:          true,
			expectHTTPStatus:   400,
			expectDetailSubstr: `malformed parameter "=abc", empty tag`,
		},
		{
			name:               "empty accounturi value is malformed",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi="},
			expectErr:          true,
			expectHTTPStatus:   400,
			expectDetailSubstr: `empty value provided for mandatory accounturi`,
		},
		{
			name:               "invalid value character is malformed",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/123;policy=wild card"},
			expectErr:          true,
			expectHTTPStatus:   400,
			expectDetailSubstr: `malformed value "wild card" for tag "policy"`,
		},
		{
			name:               "persistUntil non unix timestamp is malformed",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/123;persistUntil=not-a-unix-timestamp"},
			expectErr:          true,
			expectHTTPStatus:   400,
			expectDetailSubstr: `malformed persistUntil timestamp "not-a-unix-timestamp"`,
		},
		{
			name:               "duplicate unknown parameter is malformed",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/123;foo=bar;foo=baz"},
			expectErr:          true,
			expectHTTPStatus:   400,
			expectDetailSubstr: `duplicate parameter "foo"`,
		},
		{
			name:               "duplicate parameter is case-insensitive",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;ACCOUNTURI=https://ca.example/acct/123;accounturi=https://ca.example/acct/456"},
			expectErr:          true,
			expectHTTPStatus:   400,
			expectDetailSubstr: `duplicate parameter "accounturi"`,
		},
		{
			name:               "missing issuer-domain-name record is ignored",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{";accounturi=https://ca.example/acct/123"},
			expectErr:          true,
			expectHTTPStatus:   403,
			expectDetailSubstr: `No valid TXT record found`,
		},
		{
			name:               "wildcard policy mismatch returns unauthorized",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/123;policy=notwildcard"},
			challWildcard:      true,
			expectErr:          true,
			expectHTTPStatus:   403,
			expectDetailSubstr: `policy mismatch: expected "wildcard", got`,
		},
		{
			name:               "matching record missing accounturi returns malformed",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;policy=wildcard"},
			expectErr:          true,
			expectHTTPStatus:   400,
			expectDetailSubstr: `missing mandatory accountURI parameter`,
		},
		{
			name:               "empty persistUntil returns malformed",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/123;persistUntil="},
			expectErr:          true,
			expectHTTPStatus:   400,
			expectDetailSubstr: `malformed persistUntil timestamp`,
		},
		{
			name:               "trailing semicolon in matching record returns malformed",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/123;"},
			expectErr:          true,
			expectHTTPStatus:   400,
			expectDetailSubstr: `empty parameter or trailing semicolon provided`,
		},
		{
			name:               "expired persistUntil returns unauthorized",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/123;persistUntil=1"},
			expectErr:          true,
			expectHTTPStatus:   403,
			expectDetailSubstr: `validation time`,
		},
		{
			name:               "negative persistUntil returns unauthorized",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/123;persistUntil=-1"},
			expectErr:          true,
			expectHTTPStatus:   403,
			expectDetailSubstr: `validation time`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			addr, shutdown := startMockTXTDNSServer(t, map[string][]string{
				txtName: tc.challTXTRecords,
			})
			t.Cleanup(shutdown)

			va := VAImpl{
				customResolverAddr: addr,
				dnsClient:          new(dns.Client),
			}

			task := &vaTask{
				Identifier: acme.Identifier{
					Type:  acme.IdentifierDNS,
					Value: domain,
				},
				Challenge: &core.Challenge{
					Challenge: acme.Challenge{
						Type:              acme.ChallengeDNSPersist01,
						IssuerDomainNames: tc.challIssuerNames,
					},
				},
				AccountURL: accountURL,
				Wildcard:   tc.challWildcard,
			}

			result := va.validateDNSPersist01(task)
			if !tc.expectErr {
				if result.Error != nil {
					t.Fatalf("expected success, got error: %+v", result.Error)
				}
				return
			}

			if result.Error == nil {
				t.Fatalf("expected error, got success")
			}
			if result.Error.HTTPStatus != tc.expectHTTPStatus {
				t.Fatalf("unexpected HTTP status: got %d, want %d", result.Error.HTTPStatus, tc.expectHTTPStatus)
			}
			if !strings.Contains(result.Error.Detail, tc.expectDetailSubstr) {
				t.Fatalf("unexpected error detail: got %q, want substring %q", result.Error.Detail, tc.expectDetailSubstr)
			}
		})
	}
}

func startMockTXTDNSServer(t *testing.T, records map[string][]string) (string, func()) {
	t.Helper()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true

		for _, q := range req.Question {
			if q.Qtype != dns.TypeTXT {
				continue
			}

			values := records[strings.TrimSuffix(q.Name, ".")]
			for _, value := range values {
				resp.Answer = append(resp.Answer, &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Txt: []string{value},
				})
			}
		}

		_ = w.WriteMsg(resp)
	})

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind UDP listener: %v", err)
	}

	server := &dns.Server{
		PacketConn: conn,
		Handler:    mux,
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	return conn.LocalAddr().String(), func() {
		_ = server.Shutdown()
		_ = conn.Close()
	}
}
