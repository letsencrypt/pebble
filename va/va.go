package va

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
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

	// How many vaTasks can be in the channel before the WFE blocks on adding
	// another?
	taskQueueSize = 6

	// How many concurrent validations are performed?
	concurrentValidations = 3

	// noSleepEnvVar defines the environment variable name used to signal that the
	// VA should *not* sleep between validation attempts. Set this to 1 when you
	// invoke Pebble if you wish validation to be done at full speed, e.g.:
	//   PEBBLE_VA_NOSLEEP=1 pebble
	noSleepEnvVar = "PEBBLE_VA_NOSLEEP"
)

var IdPeAcmeIdentifierV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 30, 1}

func userAgent() string {
	return fmt.Sprintf(
		"%s (%s; %s)",
		userAgentBase, runtime.GOOS, runtime.GOARCH)
}

// certNames collects up all of a certificate's subject names (Subject CN and
// Subject Alternate Names) and reduces them to a comma joined string.
func certNames(cert *x509.Certificate) string {
	var names []string
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	names = append(names, cert.DNSNames...)
	return strings.Join(names, ", ")
}

type vaTask struct {
	Identifier string
	Challenge  *core.Challenge
	Account    *core.Account
}

type VAImpl struct {
	log      *log.Logger
	clk      clock.Clock
	httpPort int
	tlsPort  int
	tasks    chan *vaTask
	sleep    bool
}

func New(
	log *log.Logger,
	clk clock.Clock,
	httpPort, tlsPort int) *VAImpl {
	va := &VAImpl{
		log:      log,
		clk:      clk,
		httpPort: httpPort,
		tlsPort:  tlsPort,
		tasks:    make(chan *vaTask, taskQueueSize),
		sleep:    true,
	}

	// Read the PEBBLE_VA_NOSLEEP environment variable string
	noSleep := os.Getenv(noSleepEnvVar)
	// If it is set to something true-like, then the VA shouldn't sleep
	switch noSleep {
	case "1", "true", "True", "TRUE":
		va.sleep = false
		va.log.Printf("Disabling random VA sleeps")
	}

	go va.processTasks()
	return va
}

func (va VAImpl) ValidateChallenge(ident string, chal *core.Challenge, acct *core.Account) {
	task := &vaTask{
		Identifier: ident,
		Challenge:  chal,
		Account:    acct,
	}
	// Submit the task for validation
	va.tasks <- task
}

func (va VAImpl) processTasks() {
	for task := range va.tasks {
		go va.process(task)
	}
}

func (va VAImpl) firstError(results chan *core.ValidationRecord) *acme.ProblemDetails {
	for i := 0; i < concurrentValidations; i++ {
		result := <-results
		if result.Error != nil {
			return result.Error
		}
	}
	return nil
}

func (va VAImpl) process(task *vaTask) {
	va.log.Printf("Pulled a task from the Tasks queue: %#v", task)
	va.log.Printf("Starting %d validations.", concurrentValidations)

	chal := task.Challenge
	chal.Lock()
	// Update the validated date for the challenge
	now := va.clk.Now().UTC()
	chal.ValidatedDate = now
	chal.Validated = chal.ValidatedDate.Format(time.RFC3339)
	authz := chal.Authz
	chal.Unlock()

	results := make(chan *core.ValidationRecord, concurrentValidations)

	// Start a number of go routines to perform concurrent validations
	for i := 0; i < concurrentValidations; i++ {
		go va.performValidation(task, results)
	}

	err := va.firstError(results)
	// If one of the results was an error, the challenge fails
	if err != nil {
		// Lock the challenge to update the error & status
		chal.Lock()
		// Update the challenge Error
		chal.Error = err
		// Set the challenge and authorization to invalid
		chal.Status = acme.StatusInvalid
		chal.Unlock()

		// Lock the authz to update the authz status
		authz.Lock()
		authz.Status = acme.StatusInvalid
		authz.Unlock()

		va.log.Printf("authz %s set INVALID by completed challenge %s", authz.ID, chal.ID)
		// Return immediately - there's no need to check for order issuance
		return
	} else {
		// If none of the results were an error then the challenge succeeded.
		// Update the expiry for the valid authorization
		authz.Lock()
		authz.ExpiresDate = now.Add(validAuthzExpire)
		authz.Expires = authz.ExpiresDate.Format(time.RFC3339)
		authz.Status = acme.StatusValid
		authz.Unlock()

		// Set the authorization & challenge to valid
		chal.Lock()
		chal.Status = acme.StatusValid
		chal.Unlock()

		va.log.Printf("authz %s set VALID by completed challenge %s", authz.ID, chal.ID)
	}
}

func (va VAImpl) performValidation(task *vaTask, results chan<- *core.ValidationRecord) {
	if va.sleep {
		// Sleep for a random amount of time between 1-15s
		len := time.Duration(rand.Intn(15))
		va.log.Printf("Sleeping for %s seconds before validating", time.Second*len)
		va.clk.Sleep(time.Second * len)
	}

	switch task.Challenge.Type {
	case acme.ChallengeHTTP01:
		results <- va.validateHTTP01(task)
	case acme.ChallengeTLSALPN01:
		results <- va.validateTLSALPN01(task)
	case acme.ChallengeDNS01:
		results <- va.validateDNS01(task)
	default:
		va.log.Printf("Error: performValidation(): Invalid challenge type: %q", task.Challenge.Type)
	}
}

func (va VAImpl) validateDNS01(task *vaTask) *core.ValidationRecord {
	const dns01Prefix = "_acme-challenge"
	challengeSubdomain := fmt.Sprintf("%s.%s", dns01Prefix, task.Identifier)

	result := &core.ValidationRecord{
		URL:         challengeSubdomain,
		ValidatedAt: va.clk.Now(),
	}

	txts, err := net.LookupTXT(challengeSubdomain)
	if err != nil {
		result.Error = acme.UnauthorizedProblem("Error retrieving TXT records for DNS challenge")
		return result
	}

	if len(txts) == 0 {
		msg := fmt.Sprintf("No TXT records found for DNS challenge")
		result.Error = acme.UnauthorizedProblem(msg)
		return result
	}

	task.Challenge.RLock()
	expectedKeyAuthorization := task.Challenge.ExpectedKeyAuthorization(task.Account.Key)
	h := sha256.Sum256([]byte(expectedKeyAuthorization))
	task.Challenge.RUnlock()
	authorizedKeysDigest := base64.RawURLEncoding.EncodeToString(h[:])

	for _, element := range txts {
		if subtle.ConstantTimeCompare([]byte(element), []byte(authorizedKeysDigest)) == 1 {
			return result
		}
	}

	msg := fmt.Sprintf("Correct value not found for DNS challenge")
	result.Error = acme.UnauthorizedProblem(msg)
	return result
}

func (va VAImpl) validateTLSALPN01(task *vaTask) *core.ValidationRecord {
	portString := strconv.Itoa(va.tlsPort)
	hostPort := net.JoinHostPort(task.Identifier, portString)

	result := &core.ValidationRecord{
		URL:         hostPort,
		ValidatedAt: va.clk.Now(),
	}

	certs, problem := va.fetchCerts(hostPort, &tls.Config{
		ServerName: task.Identifier,
		NextProtos: []string{acme.ACMETLS1Protocol},
	})
	if problem != nil {
		result.Error = problem
		return result
	}

	leafCert := certs[0]

	// Verify SNI
	if len(leafCert.DNSNames) != 1 || !strings.EqualFold(leafCert.DNSNames[0], task.Identifier) {
		names := certNames(leafCert)
		errText := fmt.Sprintf(
			"Incorrect validation certificate for %s challenge. "+
				"Requested %s from %s. Received %d certificate(s), "+
				"first certificate had names %q",
			acme.ChallengeTLSALPN01, task.Identifier, hostPort, len(certs), names)
		result.Error = acme.UnauthorizedProblem(errText)
		return result
	}

	// Verify key authorization in acmeValidation extension
	expectedKeyAuthorization := task.Challenge.ExpectedKeyAuthorization(task.Account.Key)
	h := sha256.Sum256([]byte(expectedKeyAuthorization))
	for _, ext := range leafCert.Extensions {
		if IdPeAcmeIdentifierV1.Equal(ext.Id) && ext.Critical {
			if subtle.ConstantTimeCompare(h[:], ext.Value) == 1 {
				return result
			}
			result.Error = acme.UnauthorizedProblem("Extension acmeValidationV1 value incorrect.")
			return result
		}
	}

	return result
}

func (va VAImpl) fetchCerts(hostPort string, config *tls.Config) ([]*x509.Certificate, *acme.ProblemDetails) {
	config = config.Clone()
	config.InsecureSkipVerify = true
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second * 5}, "tcp", hostPort, config)

	if err != nil {
		// TODO(@cpu): Return better err - see parseHTTPConnError from boulder
		return nil, acme.UnauthorizedProblem(
			fmt.Sprintf("Failed to connect to %s for the %s challenge", hostPort, acme.ChallengeTLSALPN01))
	}

	// close errors are not important here
	defer func() {
		_ = conn.Close()
	}()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, acme.UnauthorizedProblem(
			fmt.Sprintf("No certs presented for %s challenge", acme.ChallengeTLSALPN01))
	}
	return certs, nil
}

func (va VAImpl) validateHTTP01(task *vaTask) *core.ValidationRecord {
	body, url, err := va.fetchHTTP(task.Identifier, task.Challenge.Token)

	result := &core.ValidationRecord{
		URL:         url,
		ValidatedAt: va.clk.Now(),
		Error:       err,
	}
	if result.Error != nil {
		return result
	}

	expectedKeyAuthorization := task.Challenge.ExpectedKeyAuthorization(task.Account.Key)
	// The server SHOULD ignore whitespace characters at the end of the body
	payload := strings.TrimRight(string(body), whitespaceCutset)
	if payload != expectedKeyAuthorization {
		result.Error = acme.UnauthorizedProblem(
			fmt.Sprintf("The key authorization file from the server did not match this challenge %q != %q",
				expectedKeyAuthorization, payload))
	}

	return result
}

// NOTE(@cpu): fetchHTTP only fetches the ACME HTTP-01 challenge path for
// a given challenge & identifier domain. It is not a challenge agnostic general
// purpose HTTP function
func (va VAImpl) fetchHTTP(identifier string, token string) ([]byte, string, *acme.ProblemDetails) {
	path := fmt.Sprintf("%s%s", acme.HTTP01BaseURL, token)

	url := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", identifier, va.httpPort),
		Path:   path,
	}

	va.log.Printf("Attempting to validate w/ HTTP: %s\n", url)
	httpRequest, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, url.String(), acme.MalformedProblem(
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
		return nil, url.String(), acme.ConnectionProblem(err.Error())
	}

	// NOTE: This is *not* using a `io.LimitedReader` and isn't suitable for
	// production because a very large response will bog down the server. Don't
	// use Pebble anywhere that isn't a testing rig!!!
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, url.String(), acme.InternalErrorProblem(err.Error())
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, url.String(), acme.InternalErrorProblem(err.Error())
	}

	if resp.StatusCode != 200 {
		return nil, url.String(), acme.UnauthorizedProblem(
			fmt.Sprintf("Non-200 status code from HTTP: %s returned %d",
				url.String(), resp.StatusCode))
	}

	return body, url.String(), nil
}
