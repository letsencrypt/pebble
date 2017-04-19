package va

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/pebble/acme"
	"github.com/letsencrypt/pebble/ca"
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
)

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
	Identifier   string
	Challenge    *core.Challenge
	Registration *core.Registration
}

type VAImpl struct {
	log      *log.Logger
	clk      clock.Clock
	httpPort int
	tlsPort  int
	tasks    chan *vaTask
	ca       *ca.CAImpl
}

func New(
	log *log.Logger,
	clk clock.Clock,
	httpPort, tlsPort int,
	ca *ca.CAImpl) *VAImpl {
	va := &VAImpl{
		log:      log,
		clk:      clk,
		httpPort: httpPort,
		tlsPort:  tlsPort,
		tasks:    make(chan *vaTask, taskQueueSize),
		ca:       ca,
	}

	go va.processTasks()
	return va
}

func (va VAImpl) ValidateChallenge(ident string, chal *core.Challenge, reg *core.Registration) {
	task := &vaTask{
		Identifier:   ident,
		Challenge:    chal,
		Registration: reg,
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

	// Lock the authz to read the order, check if it can be fulfilled
	authz.RLock()
	order := authz.Order
	authz.RUnlock()
	va.maybeIssue(order)
}

func (va VAImpl) maybeIssue(order *core.Order) {
	// Lock the order for reading to check whether all authorizations are valid
	order.RLock()
	for _, authz := range order.AuthorizationObjects {
		// Lock the authorization for reading to check its status
		authz.RLock()
		authzStatus := authz.Status
		authz.RUnlock()
		// If any of the authorizations are invalid the order isn't ready to issue
		if authzStatus != acme.StatusValid {
			return
		}
	}
	order.RUnlock()
	// All the authorizations are valid, ask the CA to complete the order in
	// a separate goroutine
	go va.ca.CompleteOrder(order)
}

func (va VAImpl) performValidation(task *vaTask, results chan<- *core.ValidationRecord) {
	// Sleep for a random amount of time between 1-15s
	len := time.Duration(rand.Intn(15))
	va.log.Printf("Sleeping for %s seconds before validating", time.Second*len)
	va.clk.Sleep(time.Second * len)

	switch task.Challenge.Type {
	case acme.ChallengeHTTP01:
		results <- va.validateHTTP01(task)
	case acme.ChallengeTLSSNI02:
		results <- va.validateTLSSNI02(task)
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

	h := sha256.New()
	task.Challenge.RLock()
	h.Write([]byte(task.Challenge.KeyAuthorization))
	task.Challenge.RUnlock()
	authorizedKeysDigest := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	for _, element := range txts {
		if subtle.ConstantTimeCompare([]byte(element), []byte(authorizedKeysDigest)) == 1 {
			return result
		}
	}

	msg := fmt.Sprintf("Correct value not found for DNS challenge")
	result.Error = acme.UnauthorizedProblem(msg)
	return result
}

func (va VAImpl) validateTLSSNI02(task *vaTask) *core.ValidationRecord {
	portString := strconv.Itoa(va.tlsPort)
	hostPort := net.JoinHostPort(task.Identifier, portString)

	result := &core.ValidationRecord{
		URL:         hostPort,
		ValidatedAt: va.clk.Now(),
	}

	const tlsSNITokenID = "token"
	const tlsSNIKaID = "ka"
	const tlsSNISuffix = "acme.invalid"

	// Lock the challenge for reading while we validate
	task.Challenge.RLock()
	defer task.Challenge.RUnlock()

	// Compute the digest for the SAN b that will appear in the certificate
	ha := sha256.Sum256([]byte(task.Challenge.Token))
	za := hex.EncodeToString(ha[:])
	sanAName := fmt.Sprintf("%s.%s.%s.%s", za[:32], za[32:], tlsSNITokenID, tlsSNISuffix)

	// Compute the digest for the SAN B that will appear in the certificate
	hb := sha256.Sum256([]byte(task.Challenge.KeyAuthorization))
	zb := hex.EncodeToString(hb[:])
	sanBName := fmt.Sprintf("%s.%s.%s.%s", zb[:32], zb[32:], tlsSNIKaID, tlsSNISuffix)

	// Perform the validation
	result.Error = va.validateTLSSNI02WithNames(hostPort, sanAName, sanBName)
	return result
}

func (va VAImpl) validateTLSSNI02WithNames(hostPort string, sanAName, sanBName string) *acme.ProblemDetails {
	certs, problem := va.fetchCerts(hostPort, sanAName)
	if problem != nil {
		return problem
	}

	leafCert := certs[0]
	if len(leafCert.DNSNames) != 2 {
		names := certNames(leafCert)
		msg := fmt.Sprintf(
			"%s challenge certificate doesn't include exactly 2 DNSName entries. "+
				"Received %d certificate(s), first certificate had names %q",
			acme.ChallengeTLSSNI02, len(certs), names)
		return acme.MalformedProblem(msg)
	}

	var validSanAName, validSanBName bool
	for _, name := range leafCert.DNSNames {
		if subtle.ConstantTimeCompare([]byte(name), []byte(sanAName)) == 1 {
			validSanAName = true
		}

		if subtle.ConstantTimeCompare([]byte(name), []byte(sanBName)) == 1 {
			validSanBName = true
		}
	}

	if !validSanAName || !validSanBName {
		names := certNames(leafCert)
		msg := fmt.Sprintf(
			"Incorrect validation certificate for %s challenge. "+
				"Requested %s from %s. Received %d certificate(s), "+
				"first certificate had names %q",
			acme.ChallengeTLSSNI02, sanAName, hostPort,
			len(certs), names)
		return acme.UnauthorizedProblem(msg)
	}

	return nil
}

func (va VAImpl) fetchCerts(hostPort string, sni string) ([]*x509.Certificate, *acme.ProblemDetails) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: time.Second * 5}, "tcp", hostPort,
		&tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		})

	if err != nil {
		// TODO(@cpu): Return better err - see parseHTTPConnError from boulder
		return nil, acme.UnauthorizedProblem(
			fmt.Sprintf("Failed to connect to %s for the %s challenge", hostPort, acme.ChallengeTLSSNI02))
	}

	// close errors are not important here
	defer func() {
		_ = conn.Close()
	}()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, acme.UnauthorizedProblem(
			fmt.Sprintf("No certs presented for %s challenge", acme.ChallengeTLSSNI02))
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

	expectedKeyAuthorization := task.Challenge.ExpectedKeyAuthorization(task.Registration.Key)
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
