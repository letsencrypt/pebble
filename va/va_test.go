package va

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestParseDNSPersistIssueValueSuccess(t *testing.T) {
	t.Parallel()
	expectedPersistUntil := time.Unix(1721952000, 0).UTC()
	testCases := []struct {
		name               string
		input              string
		expectIssuerDomain string
		expectAccountURI   string
		expectPolicy       string
		expectPersistUntil *time.Time
	}{
		{
			name:               "all known fields with whitespace",
			input:              "\tauthority.example\t;\taccounturi\t=\thttps://ca.example/acct/123\t;\tpolicy\t=\twildcard\t;\tpersistUntil\t=\t1721952000\t;\tfoo\t=\tbar\t",
			expectIssuerDomain: "authority.example",
			expectAccountURI:   "https://ca.example/acct/123",
			expectPolicy:       "wildcard",
			expectPersistUntil: &expectedPersistUntil,
		},
		{
			name:               "unknown tag with empty value",
			input:              "authority.example;accounturi=https://ca.example/acct/123;foo=",
			expectIssuerDomain: "authority.example",
			expectAccountURI:   "https://ca.example/acct/123",
		},
		{
			name:               "trailing semicolon is tolerated",
			input:              "authority.example;accounturi=https://ca.example/acct/123;",
			expectIssuerDomain: "authority.example",
			expectAccountURI:   "https://ca.example/acct/123",
		},
		{
			name:               "unknown tags are ignored",
			input:              "authority.example;accounturi=https://ca.example/acct/123;bad tag=value;\nweird=\\x01337",
			expectIssuerDomain: "authority.example",
			expectAccountURI:   "https://ca.example/acct/123",
		},
		{
			name:               "known tags and values are case-insensitive",
			input:              "authority.example;ACCOUNTURI=https://ca.example/acct/123;PoLiCy=WiLdCaRd",
			expectIssuerDomain: "authority.example",
			expectAccountURI:   "https://ca.example/acct/123",
			expectPolicy:       "WiLdCaRd",
		},
	}

	parseDNSPersistIssueValue := func(raw string) (*dnsPersistIssueValue, error) {
		issuerDomainName, paramsRaw := splitIssuerDomainName(raw)
		if issuerDomainName == "" {
			return nil, fmt.Errorf("missing issuer-domain-name")
		}
		return parseDNSPersistIssueValues(issuerDomainName, paramsRaw)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parsed, err := parseDNSPersistIssueValue(tc.input)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			if parsed.issuerDomain != tc.expectIssuerDomain {
				t.Fatalf("unexpected issuer domain: got %q, want %q", parsed.issuerDomain, tc.expectIssuerDomain)
			}
			if parsed.accountURI != tc.expectAccountURI {
				t.Fatalf("unexpected account URI: got %q, want %q", parsed.accountURI, tc.expectAccountURI)
			}
			if parsed.policy != tc.expectPolicy {
				t.Fatalf("unexpected policy: got %q, want %q", parsed.policy, tc.expectPolicy)
			}
			if tc.expectPersistUntil == nil {
				if parsed.persistUntil != nil {
					t.Fatalf("unexpected persistUntil: got %s, want nil", parsed.persistUntil)
				}
				return
			}
			if parsed.persistUntil == nil {
				t.Fatalf("expected persistUntil to be present")
			}
			if !parsed.persistUntil.Equal(*tc.expectPersistUntil) {
				t.Fatalf("unexpected persistUntil: got %s, want %s", parsed.persistUntil, tc.expectPersistUntil)
			}
		})
	}
}

func TestParseDNSPersistIssueValueErrors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		input             string
		expectErrContains string
	}{
		{
			name:              "duplicate known parameter",
			input:             "authority.example;accounturi=https://ca.example/acct/123;accounturi=https://ca.example/acct/456",
			expectErrContains: `duplicate parameter "accounturi"`,
		},
		{
			name:              "parameter missing equals",
			input:             "authority.example;accounturi=https://ca.example/acct/123;invalidparam",
			expectErrContains: `malformed parameter "invalidparam"`,
		},
		{
			name:              "persistUntil not a unix timestamp",
			input:             "authority.example;accounturi=https://ca.example/acct/123;persistUntil=not-a-unix-timestamp",
			expectErrContains: `malformed persistUntil timestamp "not-a-unix-timestamp"`,
		},
		{
			name:              "empty mandatory accounturi",
			input:             "authority.example;accounturi=",
			expectErrContains: `empty value provided for mandatory accounturi`,
		},
		{
			name:              "missing issuer-domain-name",
			input:             ";accounturi=https://ca.example/acct/123",
			expectErrContains: `missing issuer-domain-name`,
		},
		{
			name:              "policy contains disallowed whitespace",
			input:             "authority.example;accounturi=https://ca.example/acct/123;policy=wild card",
			expectErrContains: `malformed value "wild card" for tag "policy"`,
		},
		{
			name:              "duplicate unknown parameter",
			input:             "authority.example;accounturi=https://ca.example/acct/123;foo=bar;foo=baz",
			expectErrContains: `duplicate parameter "foo"`,
		},
		{
			name:              "duplicate parameter is case-insensitive",
			input:             "authority.example;ACCOUNTURI=https://ca.example/acct/123;accounturi=https://ca.example/acct/456",
			expectErrContains: `duplicate parameter "accounturi"`,
		},
	}

	parseDNSPersistIssueValue := func(raw string) (*dnsPersistIssueValue, error) {
		issuerDomainName, paramsRaw := splitIssuerDomainName(raw)
		if issuerDomainName == "" {
			return nil, fmt.Errorf("missing issuer-domain-name")
		}
		return parseDNSPersistIssueValues(issuerDomainName, paramsRaw)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseDNSPersistIssueValue(tc.input)
			if err == nil {
				t.Fatalf("expected error for %q", tc.input)
			}
			if !strings.Contains(err.Error(), tc.expectErrContains) {
				t.Errorf("unexpected error for %q: got %q, want substring %q", tc.input, err.Error(), tc.expectErrContains)
			}
		})
	}
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
			name:               "only matching malformed record returns malformed",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/123;accounturi=https://ca.example/acct/456"},
			expectErr:          true,
			expectHTTPStatus:   400,
			expectDetailSubstr: `duplicate parameter`,
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
			name:               "expired persistUntil returns unauthorized",
			challIssuerNames:   []string{"authority.example"},
			challTXTRecords:    []string{"authority.example;accounturi=https://ca.example/acct/123;persistUntil=1"},
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
