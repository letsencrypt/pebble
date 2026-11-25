package wfe

import (
	"testing"

	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/core"
)

// Once an authorization is valid, prepAuthorizationForDisplay drops the
// challenges that were not used to reach that state. Dropping one must not
// leave its read lock held, or the next writer on that challenge blocks
// forever.
func TestPrepAuthorizationForDisplayUnlocksFilteredChallenge(t *testing.T) {
	solved := &core.Challenge{
		ID: "solved",
		Challenge: acme.Challenge{
			Type:   acme.ChallengeHTTP01,
			Status: acme.StatusValid,
		},
	}
	// Still pending and carrying no error, so the authz below filters it out.
	dropped := &core.Challenge{
		ID: "dropped",
		Challenge: acme.Challenge{
			Type:   acme.ChallengeDNS01,
			Status: acme.StatusPending,
		},
	}

	authz := &core.Authorization{
		ID: "authz",
		Authorization: acme.Authorization{
			Status:     acme.StatusValid,
			Identifier: acme.Identifier{Type: acme.IdentifierDNS, Value: "example.com"},
		},
		Challenges: []*core.Challenge{solved, dropped},
	}

	displayed := prepAuthorizationForDisplay(authz)
	if len(displayed.Challenges) != 1 {
		t.Fatalf("expected only the valid challenge to be displayed, got %d challenges",
			len(displayed.Challenges))
	}
	if displayed.Challenges[0].Type != acme.ChallengeHTTP01 {
		t.Errorf("expected the http-01 challenge to be displayed, got %q",
			displayed.Challenges[0].Type)
	}

	for _, chal := range []*core.Challenge{solved, dropped} {
		if !chal.TryLock() {
			t.Errorf("challenge %q is still read locked after being prepped for display", chal.ID)
			continue
		}
		chal.Unlock()
	}
}
