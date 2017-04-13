package va

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"runtime"
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

type vaTask struct {
	Identifier   string
	Challenge    *core.Challenge
	Registration *core.Registration
}

type VAImpl struct {
	log      *log.Logger
	clk      clock.Clock
	httpPort int
	tasks    chan *vaTask
	ca       *ca.CAImpl
}

func New(log *log.Logger, clk clock.Clock, httpPort int, ca *ca.CAImpl) *VAImpl {
	va := &VAImpl{
		log:      log,
		clk:      clk,
		httpPort: httpPort,
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

	// TODO(@cpu): Implement validation for DNS-01, TLS-SNI-02, etc
	switch task.Challenge.Type {
	case acme.ChallengeHTTP01:
		results <- va.validateHTTP01(task)
	default:
		va.log.Printf("Error: performValidation(): Invalid challenge type: %q", task.Challenge.Type)
	}
}

func (va VAImpl) validateHTTP01(task *vaTask) *core.ValidationRecord {
	body, url, err := va.fetchHTTP(task.Identifier, task.Challenge.Token)

	result := &core.ValidationRecord{
		URL:         url,
		ValidatedAt: va.clk.Now(),
	}
	if err != nil {
		result.Error = err
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
