package va

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/pebble/acme"
	"github.com/letsencrypt/pebble/core"
)

const (
	whitespaceCutset = "\n\r\t"
	userAgentBase    = "LetsEncrypt-Pebble-VA"

	// How long do valid authorizations last before expiring?
	validAuthzExpire = time.Hour
)

func userAgent() string {
	return fmt.Sprintf(
		"%s (%s; %s)",
		userAgentBase, runtime.GOOS, runtime.GOARCH)
}

type VAImpl struct {
	log      *log.Logger
	clk      clock.Clock
	httpPort int
}

func New(log *log.Logger, clk clock.Clock, httpPort int) *VAImpl {
	return &VAImpl{
		log:      log,
		clk:      clk,
		httpPort: httpPort,
	}
}

func (va VAImpl) Validate(identifier string, chal *core.Challenge, reg *core.Registration) error {
	// TODO(@cpu): Implement validation for DNS-01, TLS-SNI-02, etc
	var prob *acme.ProblemDetails
	switch chal.Type {
	case acme.ChallengeHTTP01:
		prob = va.validateHTTP01(identifier, chal, reg)
	default:
		return fmt.Errorf("Invalid challenge type: %q", chal.Type)
	}

	authz := chal.Authz
	now := va.clk.Now().UTC()
	// Update the validated date for the challenge regardless of good/bad outcome
	chal.ValidatedDate = now
	chal.Validated = chal.ValidatedDate.Format(time.RFC3339)
	if prob != nil {
		// Update the challenge Error
		chal.Error = prob
		// Set the challenge and authorization to invalid
		chal.Status = acme.StatusInvalid
		authz.Status = acme.StatusInvalid
	} else {
		// Update the expiry for the valid authorization
		authz.ExpiresDate = now.Add(validAuthzExpire)
		authz.Expires = authz.ExpiresDate.Format(time.RFC3339)
		// Set the authorization & challenge to valid
		chal.Status = acme.StatusValid
		authz.Status = acme.StatusValid
	}

	return nil
}

func (va VAImpl) validateHTTP01(
	identifier string,
	chal *core.Challenge,
	reg *core.Registration,
) *acme.ProblemDetails {
	body, err := va.fetchHTTP(identifier, chal)
	if err != nil {
		return err
	}

	expectedKeyAuthorization := chal.ExpectedKeyAuthorization(reg.Key)
	// The server SHOULD ignore whitespace characters at the end of the body
	payload := strings.TrimRight(string(body), whitespaceCutset)
	if payload != expectedKeyAuthorization {
		return acme.UnauthorizedProblem(
			fmt.Sprintf("The key authorization file from the server did not match this challenge %q != %q",
				expectedKeyAuthorization, payload))
	}

	return nil
}

// NOTE(@cpu): fetchHTTP only fetches the ACME HTTP-01 challenge path for
// a given challenge & identifier domain. It is not a challenge agnostic general
// purpose HTTP function
func (va VAImpl) fetchHTTP(identifier string, chal *core.Challenge) ([]byte, *acme.ProblemDetails) {
	path := fmt.Sprintf("%s%s", acme.HTTP01BaseURL, chal.Token)

	url := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", chal.Authz.Identifier.Value, va.httpPort),
		Path:   path,
	}

	chal.ValidationRecords = []acme.ValidationRecord{
		acme.ValidationRecord{url.String()},
	}
	va.log.Printf("Attempting to validate %s: %s\n", chal.Type, url)
	httpRequest, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, acme.MalformedProblem(
			fmt.Sprintf("Invalid URL %q\n", url.String()))
	}
	httpRequest.Header.Set("User-Agent", userAgent())
	httpRequest.Header.Set("Accept", "*/*")

	transport := &http.Transport{
		// We don't expect to make multiple requests to a client, so close
		// connection immediately.
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 5,
	}

	resp, err := client.Do(httpRequest)
	if err != nil {
		return nil, acme.ConnectionProblem(err.Error())
	}

	// NOTE: This is *not* using a `io.LimitedReader` and isn't suitable for
	// production because a very large response will bog down the server. Don't
	// use Pebble anywhere that isn't a testing rig!!!
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, acme.InternalErrorProblem(err.Error())
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, acme.InternalErrorProblem(err.Error())
	}

	if resp.StatusCode != 200 {
		return nil, acme.UnauthorizedProblem(
			fmt.Sprintf("Non-200 status code from HTTP: %s returned %d",
				url.String(), resp.StatusCode))
	}

	return body, nil
}
