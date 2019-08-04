package va

import (
	"context"
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

	"github.com/miekg/dns"

	"github.com/letsencrypt/challtestsrv"
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

	// sleepTimeEnvVar defines the environment variable name used to set the time
	// the VA should sleep between validation attempts (if not disabled). Set this
	// e.g. to 5 when you invoke Pebble if you wish the delays to be between 0
	// and 5 seconds (instead between 0 and 15 seconds):
	//   PEBBLE_VA_SLEEPTIME=5 pebble
	sleepTimeEnvVar = "PEBBLE_VA_SLEEPTIME"

	// defaultSleepTime defines the default sleep time (in seconds) between
	// validation attempts. Can be disabled or modified by the environment
	// variables PEBBLE_VA_NOSLEEP resp. PEBBLE_VA_SLEEPTIME (see above).
	defaultSleepTime = 5

	// validationTimeout defines the timeout for validation attempts.
	validationTimeout = 15 * time.Second

	// noValidateEnvVar defines the environment variable name used to signal that
	// the VA should *not* actually validate challenges. Set this to 1 when you
	// invoke Pebble if you wish validation to always succeed without actually
	// making any challenge requests, e.g.:
	//   PEBBLE_VA_ALWAYS_VALID=1 pebble"
	noValidateEnvVar = "PEBBLE_VA_ALWAYS_VALID"
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
	Identifier acme.Identifier
	Challenge  *core.Challenge
	Account    *core.Account
}

type VAImpl struct {
	log                *log.Logger
	httpPort           int
	tlsPort            int
	tasks              chan *vaTask
	sleep              bool
	sleepTime          int
	alwaysValid        bool
	strict             bool
	customResolverAddr string
	dnsClient          *dns.Client
}

func New(
	log *log.Logger,
	httpPort, tlsPort int,
	strict bool, customResolverAddr string) *VAImpl {
	va := &VAImpl{
		log:                log,
		httpPort:           httpPort,
		tlsPort:            tlsPort,
		tasks:              make(chan *vaTask, taskQueueSize),
		sleep:              true,
		sleepTime:          defaultSleepTime,
		strict:             strict,
		customResolverAddr: customResolverAddr,
	}

	if customResolverAddr != "" {
		va.log.Printf("Using custom DNS resolver for ACME challenges: %s", customResolverAddr)
		va.dnsClient = new(dns.Client)
	} else {
		va.log.Print("Using system DNS resolver for ACME challenges")
	}

	// Read the PEBBLE_VA_NOSLEEP environment variable string
	noSleep := os.Getenv(noSleepEnvVar)
	// If it is set to something true-like, then the VA shouldn't sleep
	switch noSleep {
	case "1", "true", "True", "TRUE":
		va.sleep = false
		va.log.Printf("Disabling random VA sleeps")
	}

	sleepTime := os.Getenv(sleepTimeEnvVar)
	sleepTimeInt, err := strconv.Atoi(sleepTime)
	if err == nil && va.sleep && sleepTimeInt >= 1 {
		va.sleepTime = sleepTimeInt
		va.log.Printf("Setting maximum random VA sleep time to %d seconds", va.sleepTime)
	}

	noValidate := os.Getenv(noValidateEnvVar)
	switch noValidate {
	case "1", "true", "True", "TRUE":
		va.alwaysValid = true
		va.log.Printf("Disabling VA challenge requests. VA always returns valid")
	}

	go va.processTasks()
	return va
}

func (va VAImpl) ValidateChallenge(ident acme.Identifier, chal *core.Challenge, acct *core.Account) {
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

// setAuthzValid updates an authorization and an associated challenge to be
// status valid. The authorization expiry is updated to now plus the configured
// `validAuthzExpire` duration.
func (va VAImpl) setAuthzValid(authz *core.Authorization, chal *core.Challenge) {
	authz.Lock()
	defer authz.Unlock()
	// Update the authz expiry for the new validity period
	now := time.Now().UTC()
	authz.ExpiresDate = now.Add(validAuthzExpire)
	authz.Expires = authz.ExpiresDate.Format(time.RFC3339)
	// Update the authz status
	authz.Status = acme.StatusValid

	chal.Lock()
	defer chal.Unlock()
	// Update the challenge status
	chal.Status = acme.StatusValid
}

// setOrderError updates an order with an error from an authorization
// validation.
func (va VAImpl) setOrderError(order *core.Order, err *acme.ProblemDetails) {
	order.Lock()
	defer order.Unlock()
	order.Error = err
}

// setAuthzInvalid updates an authorization and an associated challenge to be
// status invalid. The challenge's error is set to the provided problem and both
// the challenge and the authorization have their status updated to invalid.
func (va VAImpl) setAuthzInvalid(
	authz *core.Authorization,
	chal *core.Challenge,
	err *acme.ProblemDetails) {
	authz.Lock()
	defer authz.Unlock()
	// Update the authz status
	authz.Status = acme.StatusInvalid

	// Lock the challenge for update
	chal.Lock()
	defer chal.Unlock()
	// Update the challenge error field
	chal.Error = err
	// Update the challenge status
	chal.Status = acme.StatusInvalid
}

func (va VAImpl) process(task *vaTask) {
	va.log.Printf("Pulled a task from the Tasks queue: %#v", task)
	va.log.Printf("Starting %d validations.", concurrentValidations)

	chal := task.Challenge
	chal.Lock()
	// Update the validated date for the challenge
	now := time.Now().UTC()
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
		va.setAuthzInvalid(authz, chal, err)
		va.log.Printf("authz %s set INVALID by completed challenge %s", authz.ID, chal.ID)
		va.setOrderError(authz.Order, err)
		va.log.Printf("order %s set INVALID by invalid authz %s", authz.Order.ID, authz.ID)
		return
	}

	// If there was no error, then the challenge succeeded and the authz is valid
	va.setAuthzValid(authz, chal)
	va.log.Printf("authz %s set VALID by completed challenge %s", authz.ID, chal.ID)
}

func (va VAImpl) performValidation(task *vaTask, results chan<- *core.ValidationRecord) {
	if va.sleep {
		// Sleep for a random amount of time between 0 and va.sleepTime seconds
		len := time.Duration(rand.Intn(va.sleepTime))
		va.log.Printf("Sleeping for %s seconds before validating", time.Second*len)
		time.Sleep(time.Second * len)
	}

	// If `alwaysValid` is true then return a validation record immediately
	// without actually making any validation requests.
	if va.alwaysValid {
		va.log.Printf("%s is enabled. Skipping real validation of challenge %s",
			noValidateEnvVar, task.Challenge.ID)
		// NOTE(@cpu): The validation record's URL will not match the value it would
		// have received in a real validation request. For simplicity when faking
		// validation we always set it to the task identifier regardless of challenge
		// type. For example comparison, a real DNS-01 validation would set
		// the URL to the `_acme-challenge` subdomain.
		results <- &core.ValidationRecord{
			URL:         task.Identifier.Value,
			ValidatedAt: time.Now(),
		}
		return
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
	challengeSubdomain := fmt.Sprintf("%s.%s", dns01Prefix, task.Identifier.Value)

	result := &core.ValidationRecord{
		URL:         challengeSubdomain,
		ValidatedAt: time.Now(),
	}

	txts, err := va.getTXTEntry(challengeSubdomain)
	if err != nil {
		result.Error = acme.UnauthorizedProblem(fmt.Sprintf("Error retrieving TXT records for DNS challenge (%q)", err))
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

	var serverNameIdentifier string
	switch task.Identifier.Type {
	case acme.IdentifierDNS:
		serverNameIdentifier = task.Identifier.Value
	case acme.IdentifierIP:
		serverNameIdentifier = reverseaddr(task.Identifier.Value)
	}
	result := &core.ValidationRecord{
		URL:         net.JoinHostPort(task.Identifier.Value, portString),
		ValidatedAt: time.Now(),
	}

	addrs, err := va.resolveIP(task.Identifier.Value)

	if err != nil {
		result.Error = acme.MalformedProblem(
			fmt.Sprintf("Error occurred while resolving URL %q: %q", task.Identifier.Value, err))
		return result
	}

	if len(addrs) == 0 {
		result.Error = acme.MalformedProblem(
			fmt.Sprintf("Could not resolve URL %q", task.Identifier.Value))
		return result
	}

	cs, problem := va.fetchConnectionState(net.JoinHostPort(addrs[0], portString), &tls.Config{
		ServerName:         serverNameIdentifier,
		NextProtos:         []string{acme.ACMETLS1Protocol},
		InsecureSkipVerify: true,
	})
	if problem != nil {
		result.Error = problem
		return result
	}

	if !cs.NegotiatedProtocolIsMutual || cs.NegotiatedProtocol != acme.ACMETLS1Protocol {
		result.Error = acme.UnauthorizedProblem(fmt.Sprintf(
			"Cannot negotiate ALPN protocol %q for %s challenge",
			acme.ACMETLS1Protocol,
			acme.ChallengeTLSALPN01,
		))
		return result
	}

	certs := cs.PeerCertificates
	if len(certs) == 0 {
		result.Error = acme.UnauthorizedProblem(fmt.Sprintf("No certs presented for %s challenge", acme.ChallengeTLSALPN01))
		return result
	}
	leafCert := certs[0]

	// Verify SNI - certificate returned must be issued only for the domain we are verifying.
	var namematch bool
	switch task.Identifier.Type {
	case acme.IdentifierDNS:
		namematch = len(leafCert.DNSNames) == 1 && strings.EqualFold(leafCert.DNSNames[0], task.Identifier.Value)
	case acme.IdentifierIP:
		namematch = len(leafCert.IPAddresses) == 1 && leafCert.IPAddresses[0].Equal(net.ParseIP(task.Identifier.Value))
	default:
		namematch = false
	}
	if !namematch {
		names := certNames(leafCert)
		errText := fmt.Sprintf(
			"Incorrect validation certificate for %s challenge. "+
				"Requested %s from %s. Received %d certificate(s), "+
				"first certificate had names %q",
			acme.ChallengeTLSALPN01, task.Identifier, net.JoinHostPort(task.Identifier.Value, portString), len(certs), names)
		result.Error = acme.UnauthorizedProblem(errText)
		return result
	}

	// Verify key authorization in acmeValidation extension
	expectedKeyAuthorization := task.Challenge.ExpectedKeyAuthorization(task.Account.Key)
	h := sha256.Sum256([]byte(expectedKeyAuthorization))
	for _, ext := range leafCert.Extensions {
		if ext.Critical {
			hasAcmeIdentifier := challtestsrv.IDPeAcmeIdentifier.Equal(ext.Id)
			if hasAcmeIdentifier {
				var extValue []byte
				if _, err := asn1.Unmarshal(ext.Value, &extValue); err != nil {
					errText := fmt.Sprintf("Incorrect validation certificate for %s challenge. "+
						"Malformed acmeValidation extension value.", acme.ChallengeTLSALPN01)
					result.Error = acme.UnauthorizedProblem(errText)
					return result
				}
				if subtle.ConstantTimeCompare(h[:], extValue) == 1 {
					return result
				}
				errText := fmt.Sprintf("Incorrect validation certificate for %s challenge. "+
					"Invalid acmeValidation extension value.", acme.ChallengeTLSALPN01)
				result.Error = acme.UnauthorizedProblem(errText)
				return result
			}
		}
	}

	errText := fmt.Sprintf(
		"Incorrect validation certificate for %s challenge. "+
			"Missing acmeValidationV1 extension.",
		acme.ChallengeTLSALPN01)
	result.Error = acme.UnauthorizedProblem(errText)
	return result
}

func (va VAImpl) fetchConnectionState(hostPort string, config *tls.Config) (*tls.ConnectionState, *acme.ProblemDetails) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: validationTimeout}, "tcp", hostPort, config)

	if err != nil {
		// TODO(@cpu): Return better err - see parseHTTPConnError from boulder
		return nil, acme.UnauthorizedProblem(
			fmt.Sprintf("Failed to connect to %s for the %s challenge", hostPort, acme.ChallengeTLSALPN01))
	}

	// close errors are not important here
	defer func() {
		_ = conn.Close()
	}()

	cs := conn.ConnectionState()
	return &cs, nil
}

func (va VAImpl) validateHTTP01(task *vaTask) *core.ValidationRecord {
	body, url, err := va.fetchHTTP(task.Identifier.Value, task.Challenge.Token)

	result := &core.ValidationRecord{
		URL:         url,
		ValidatedAt: time.Now(),
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
	portString := strconv.Itoa(va.httpPort)

	url := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(identifier, portString),
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

	addrs, err := va.resolveIP(identifier)

	if err != nil {
		return nil, url.String(), acme.MalformedProblem(
			fmt.Sprintf("Error occurred while resolving URL %q: %q", url.String(), err))
	}

	if len(addrs) == 0 {
		return nil, url.String(), acme.MalformedProblem(
			fmt.Sprintf("Could not resolve URL %q", url.String()))
	}

	transport := &http.Transport{
		// We don't expect to make multiple requests to a client, so close
		// connection immediately.
		DisableKeepAlives: true,

		// We always ask for a challenge on HTTP, but
		// we should ignore certificate errors if we get redirected
		// to an HTTPS host.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},

		// Control specifically which IP will be used for this request
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0], portString))
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   validationTimeout,
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

// getTXTEntry fetches TXT entries for the given domain name using the recursive resolver located at
// `va.customResolverAddr`, or the default system resolver if no custom resolver addr is specified
func (va VAImpl) getTXTEntry(name string) ([]string, error) {
	ctx, cancelfunc := context.WithTimeout(context.Background(), validationTimeout)
	defer cancelfunc()

	if va.customResolverAddr == "" {
		return net.DefaultResolver.LookupTXT(ctx, name)
	}

	var txts []string
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	in, _, err := va.dnsClient.ExchangeContext(ctx, message, va.customResolverAddr)

	if err != nil {
		return nil, err
	}

	if in.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS lookup for %q returned an unsuccessful response: %q", name, in.Rcode)
	}

	for _, record := range in.Answer {
		if t, ok := record.(*dns.TXT); ok {
			txts = append(txts, t.Txt...)
		}
	}

	return txts, nil
}

// resolveIP find all IPs for the given domain name using the recursive resolver located at
// `va.customResolverAddr`, or the default system resolver if no custom resolver addr is specified
func (va VAImpl) resolveIP(name string) ([]string, error) {
	ctx, cancelfunc := context.WithTimeout(context.Background(), validationTimeout)
	defer cancelfunc()

	if va.customResolverAddr == "" {
		return net.DefaultResolver.LookupHost(ctx, name)
	}

	// Check if the given name is not already an IP. If it is the case, just return it untouched.
	addrs := []string{}
	parsed := net.ParseIP(name)
	if parsed != nil {
		addrs = append(addrs, name)
		return addrs, nil
	}

	messageAAAA := new(dns.Msg)
	messageAAAA.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	inAAAA, _, err := va.dnsClient.ExchangeContext(ctx, messageAAAA, va.customResolverAddr)

	if err != nil {
		return nil, err
	}

	for _, record := range inAAAA.Answer {
		if t, ok := record.(*dns.AAAA); ok {
			addrs = append(addrs, t.AAAA.String())
		}
	}

	messageA := new(dns.Msg)
	messageA.SetQuestion(dns.Fqdn(name), dns.TypeA)
	inA, _, err := va.dnsClient.ExchangeContext(ctx, messageA, va.customResolverAddr)

	if err != nil {
		return nil, err
	}

	for _, record := range inA.Answer {
		if t, ok := record.(*dns.A); ok {
			addrs = append(addrs, t.A.String())
		}
	}

	return addrs, nil
}

// reverseaddr function is borrowed from net/dnsclient.go[0] and the Go std library.
// [0]: https://golang.org/src/net/dnsclient.go
func reverseaddr(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	// Apperently IP type in net package saves all ip in ipv6 formant, from biggest byte to smallest. we need last 4 bytes, so ip[15] to ip[12]
	if ip.To4() != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip[15], ip[14], ip[13], ip[12])
	}
	// Must be IPv6
	buf := make([]string, 0, len(ip)+1)
	// Add it, in reverse, to the buffer
	for i := len(ip) - 1; i >= 0; i-- {
		buf = append(buf, fmt.Sprintf("%x.%x", ip[i]&0x0F, ip[i]>>4))
	}
	// Append "ip6.arpa." and return (buf already has the final '.') see RFC3152 for how this address is constructed.
	buf = append(buf, "ip6.arpa.")
	return strings.Join(buf, ".")
}
