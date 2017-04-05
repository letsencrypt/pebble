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
	"sync"
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

	// How many VATasks can be in the channel before the WFE blocks on adding
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
	Results      chan core.ValidationRecord
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
		Results:      make(chan core.ValidationRecord, concurrentValidations),
	}
	// Submit the task for validation
	va.tasks <- task
}

func (va VAImpl) processTasks() {
TaskLoop:
	for {
		// Pull a task off of the tasks channel
		task, ok := <-va.tasks
		if !ok {
			break
		}
		va.log.Printf("Pulled a task from the Tasks queue: %#v", task)
		va.log.Printf("Starting %d validations.", concurrentValidations)

		var wg sync.WaitGroup
		wg.Add(concurrentValidations)
		// Start a number of go routines to perform concurrent validations
		for i := 0; i < concurrentValidations; i++ {
			go va.performValidation(task, &wg)
		}
		va.log.Printf("Waiting on validations")
		// Wait for all of the go routines to finish
		wg.Wait()
		va.log.Printf("All %d validations finished.\n", concurrentValidations)

		chal := task.Challenge
		authz := chal.Authz

		// Update the validated date for the challenge regardless of good/bad outcome
		now := va.clk.Now().UTC()
		chal.ValidatedDate = now
		chal.Validated = chal.ValidatedDate.Format(time.RFC3339)

		// Read a validation result from the task results channel for each of the
		// concurrent validations into a slice for processing.
		for i := 0; i < concurrentValidations; i++ {
			va.log.Printf("Reading a result from task.Results")
			result := <-task.Results

			// If one of the results was an error, the challenge fails
			if result.Error != nil {
				// Update the challenge Error
				chal.Error = result.Error
				// Set the challenge and authorization to invalid
				chal.Status = acme.StatusInvalid
				authz.Status = acme.StatusInvalid
				va.log.Printf("authz %s set INVALID by completed challenge %s", authz.ID, chal.ID)
				// Continue immediately, the challenge is finished
				continue TaskLoop
			}
		}

		// If none of the results were an error then the challenge succeeded.
		// Update the expiry for the valid authorization
		authz.ExpiresDate = now.Add(validAuthzExpire)
		authz.Expires = authz.ExpiresDate.Format(time.RFC3339)
		// Set the authorization & challenge to valid
		chal.Status = acme.StatusValid
		authz.Status = acme.StatusValid
		va.log.Printf("authz %s set VALID by completed challenge %s", authz.ID, chal.ID)

		// Check whether validating this authorization completed the overall order
		// TODO(@cpu): this will race if another thread updates an authorization for this order
		order := authz.Order
		for _, authz := range order.AuthorizationObjects {
			// If any of the authorizations are invalid the order isn't ready to issue
			if authz.Status != acme.StatusValid {
				continue TaskLoop
			}
		}
		// Ask the CA to complete the order in a separate goroutine
		go va.ca.CompleteOrder(order)
	}
}

func (va VAImpl) performValidation(task *vaTask, wg *sync.WaitGroup) {
	// Sleep for a random amount of time between 1-15s
	len := time.Duration(rand.Intn(15))
	va.log.Printf("Sleeping for %s seconds before validating", time.Second*len)
	va.clk.Sleep(time.Second * len)

	// TODO(@cpu): Implement validation for DNS-01, TLS-SNI-02, etc
	switch task.Challenge.Type {
	case acme.ChallengeHTTP01:
		va.validateHTTP01(task)
	default:
		va.log.Printf("Error: performValidation(): Invalid challenge type: %q", task.Challenge.Type)
	}
	va.log.Printf("Finished a performValidation()")
	wg.Done()
}

func (va VAImpl) validateHTTP01(task *vaTask) {
	va.log.Printf("Validating HTTP01")
	body, url, err := va.fetchHTTP(task.Identifier, task.Challenge.Token)

	result := core.ValidationRecord{
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

	va.log.Printf("Returning result for validation task: %#v", result)
	// Return the validation record
	task.Results <- result
	va.log.Printf("Wrote result.")
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
