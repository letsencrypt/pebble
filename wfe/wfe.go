package wfe

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/square/go-jose.v2"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/pebble/acme"
	"github.com/letsencrypt/pebble/ca"
	"github.com/letsencrypt/pebble/core"
	"github.com/letsencrypt/pebble/db"
	"github.com/letsencrypt/pebble/va"
)

const (
	// Note: We deliberately pick endpoint paths that differ from Boulder to
	// exercise clients processing of the /directory response
	directoryPath     = "/dir"
	noncePath         = "/nonce-plz"
	newAccountPath    = "/sign-me-up"
	acctPath          = "/my-account/"
	newOrderPath      = "/order-plz"
	orderPath         = "/my-order/"
	orderFinalizePath = "/finalize-order/"
	authzPath         = "/authZ/"
	challengePath     = "/chalZ/"
	certPath          = "/certZ/"

	// How long do pending authorizations last before expiring?
	pendingAuthzExpire = time.Hour

	// How many contacts is an account allowed to have?
	maxContactsPerAcct = 2

	// badNonceEnvVar defines the environment variable name used to provide
	// a percentage value for how often good nonces should be rejected as if they
	// were bad. This can be used to exercise client nonce handling/retries.
	// To have the WFE not reject any good nonces, run Pebble like:
	//   PEBBLE_WFE_NONCEREJECT=0 pebble
	// To have the WFE reject 15% of good nonces, run Pebble like:
	//   PEBBLE_WFE_NONCEREJECT=15
	badNonceEnvVar = "PEBBLE_WFE_NONCEREJECT"

	// By default when no PEBBLE_WFE_NONCEREJECT is set, what percentage of good
	// nonces are rejected?
	defaultNonceReject = 15
)

type requestEvent struct {
	ClientAddr string `json:",omitempty"`
	Endpoint   string `json:",omitempty"`
	Method     string `json:",omitempty"`
	UserAgent  string `json:",omitempty"`
}

type wfeHandlerFunc func(context.Context, *requestEvent, http.ResponseWriter, *http.Request)

func (f wfeHandlerFunc) ServeHTTP(e *requestEvent, w http.ResponseWriter, r *http.Request) {
	ctx := context.TODO()
	f(ctx, e, w, r)
}

type wfeHandler interface {
	ServeHTTP(e *requestEvent, w http.ResponseWriter, r *http.Request)
}

type topHandler struct {
	wfe wfeHandler
}

func (th *topHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO(@cpu): consider restoring X-Forwarded-For handling for ClientAddr
	rEvent := &requestEvent{
		ClientAddr: r.RemoteAddr,
		Method:     r.Method,
		UserAgent:  r.Header.Get("User-Agent"),
	}

	th.wfe.ServeHTTP(rEvent, w, r)
}

type WebFrontEndImpl struct {
	log             *log.Logger
	db              *db.MemoryStore
	nonce           *nonceMap
	nonceErrPercent int
	clk             clock.Clock
	va              *va.VAImpl
	ca              *ca.CAImpl
}

const ToSURL = "data:text/plain,Do%20what%20thou%20wilt"

func New(
	log *log.Logger,
	clk clock.Clock,
	db *db.MemoryStore,
	va *va.VAImpl,
	ca *ca.CAImpl) WebFrontEndImpl {

	// Read the % of good nonces that should be rejected as bad nonces from the
	// environment
	nonceErrPercentVal := os.Getenv(badNonceEnvVar)
	var nonceErrPercent int

	// Parse the env var value as a base 10 int - if there isn't an error, use it
	// as the wfe nonceErrPercent
	if val, err := strconv.ParseInt(nonceErrPercentVal, 10, 0); err == nil {
		nonceErrPercent = int(val)
	} else {
		// Otherwise just use the default
		nonceErrPercent = defaultNonceReject
	}

	// If the value is out of the range just clip it sensibly
	if nonceErrPercent < 0 {
		nonceErrPercent = 0
	} else if nonceErrPercent > 100 {
		nonceErrPercent = 99
	}
	log.Printf("Configured to reject %d%% of good nonces", nonceErrPercent)

	return WebFrontEndImpl{
		log:             log,
		db:              db,
		nonce:           newNonceMap(),
		nonceErrPercent: nonceErrPercent,
		clk:             clk,
		va:              va,
		ca:              ca,
	}
}

func (wfe *WebFrontEndImpl) HandleFunc(
	mux *http.ServeMux,
	pattern string,
	handler wfeHandlerFunc,
	methods ...string) {

	methodsMap := make(map[string]bool)
	for _, m := range methods {
		methodsMap[m] = true
	}

	if methodsMap["GET"] && !methodsMap["HEAD"] {
		// Allow HEAD for any resource that allows GET
		methods = append(methods, "HEAD")
		methodsMap["HEAD"] = true
	}

	methodsStr := strings.Join(methods, ", ")
	defaultHandler := http.StripPrefix(pattern,
		&topHandler{
			wfe: wfeHandlerFunc(func(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Replay-Nonce", wfe.nonce.createNonce())

				logEvent.Endpoint = pattern
				if request.URL != nil {
					logEvent.Endpoint = path.Join(logEvent.Endpoint, request.URL.Path)
				}

				addNoCacheHeader(response)

				if !methodsMap[request.Method] {
					response.Header().Set("Allow", methodsStr)
					wfe.sendError(acme.MethodNotAllowed(), response)
					return
				}

				wfe.log.Printf("%s %s -> calling handler()\n", request.Method, logEvent.Endpoint)

				// TODO(@cpu): Configureable request timeout
				timeout := 1 * time.Minute
				ctx, cancel := context.WithTimeout(ctx, timeout)
				handler(ctx, logEvent, response, request)
				cancel()
			},
			)})
	mux.Handle(pattern, defaultHandler)
}

func (wfe *WebFrontEndImpl) sendError(prob *acme.ProblemDetails, response http.ResponseWriter) {
	problemDoc, err := marshalIndent(prob)
	if err != nil {
		problemDoc = []byte("{\"detail\": \"Problem marshalling error message.\"}")
	}

	response.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	response.WriteHeader(prob.HTTPStatus)
	response.Write(problemDoc)
}

func (wfe *WebFrontEndImpl) Handler() http.Handler {
	m := http.NewServeMux()
	wfe.HandleFunc(m, directoryPath, wfe.Directory, "GET")
	// Note for noncePath: "GET" also implies "HEAD"
	wfe.HandleFunc(m, noncePath, wfe.Nonce, "GET")
	wfe.HandleFunc(m, newAccountPath, wfe.NewAccount, "POST")
	wfe.HandleFunc(m, newOrderPath, wfe.NewOrder, "POST")
	wfe.HandleFunc(m, orderPath, wfe.Order, "GET")
	wfe.HandleFunc(m, orderFinalizePath, wfe.FinalizeOrder, "POST")
	wfe.HandleFunc(m, authzPath, wfe.Authz, "GET")
	wfe.HandleFunc(m, challengePath, wfe.Challenge, "GET", "POST")
	wfe.HandleFunc(m, certPath, wfe.Certificate, "GET")

	// TODO(@cpu): Handle POST to acctPath for existing account updates
	return m
}

func (wfe *WebFrontEndImpl) Directory(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	directoryEndpoints := map[string]string{
		"newNonce":   noncePath,
		"newAccount": newAccountPath,
		"newOrder":   newOrderPath,
	}

	response.Header().Set("Content-Type", "application/json; charset=utf-8")

	relDir, err := wfe.relativeDirectory(request, directoryEndpoints)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("unable to create directory"), response)
		return
	}

	response.Write(relDir)
}

func (wfe *WebFrontEndImpl) relativeDirectory(request *http.Request, directory map[string]string) ([]byte, error) {
	// Create an empty map sized equal to the provided directory to store the
	// relative-ized result
	relativeDir := make(map[string]interface{}, len(directory))

	for k, v := range directory {
		relativeDir[k] = wfe.relativeEndpoint(request, v)
	}
	relativeDir["meta"] = map[string]string{
		"termsOfService": ToSURL,
	}

	directoryJSON, err := marshalIndent(relativeDir)
	// This should never happen since we are just marshalling known strings
	if err != nil {
		return nil, err
	}
	return directoryJSON, nil
}

func (wfe *WebFrontEndImpl) relativeEndpoint(request *http.Request, endpoint string) string {
	proto := "http"
	host := request.Host

	// If the request was received via TLS, use `https://` for the protocol
	if request.TLS != nil {
		proto = "https"
	}

	// Allow upstream proxies  to specify the forwarded protocol. Allow this value
	// to override our own guess.
	if specifiedProto := request.Header.Get("X-Forwarded-Proto"); specifiedProto != "" {
		proto = specifiedProto
	}

	// Default to "localhost" when no request.Host is provided. Otherwise requests
	// with an empty `Host` produce results like `http:///acme/new-authz`
	if request.Host == "" {
		host = "localhost"
	}

	resultUrl := url.URL{Scheme: proto, Host: host, Path: endpoint}
	return resultUrl.String()
}

func (wfe *WebFrontEndImpl) Nonce(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {
	response.WriteHeader(http.StatusNoContent)
}

/*
 * keyToID produces a string with the hex representation of the SHA256 digest
 * over a provided public key. We use this for acme.Account ID values
 * because it makes looking up a account by key easy (required by the spec
 * for retreiving existing account), and becauase it makes the reg URLs
 * somewhat human digestable/comparable.
 */
func keyToID(key crypto.PublicKey) (string, error) {
	switch t := key.(type) {
	case *jose.JSONWebKey:
		if t == nil {
			return "", fmt.Errorf("Cannot compute ID of nil key")
		}
		return keyToID(t.Key)
	case jose.JSONWebKey:
		return keyToID(t.Key)
	default:
		keyDER, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", err
		}
		spkiDigest := sha256.Sum256(keyDER)
		return hex.EncodeToString(spkiDigest[:]), nil
	}
}

func (wfe *WebFrontEndImpl) parseJWS(body string) (*jose.JSONWebSignature, error) {
	// Parse the raw JWS JSON to check that:
	// * the unprotected Header field is not being used.
	// * the "signatures" member isn't present, just "signature".
	//
	// This must be done prior to `jose.parseSigned` since it will strip away
	// these headers.
	var unprotected struct {
		Header     map[string]string
		Signatures []interface{}
	}
	if err := json.Unmarshal([]byte(body), &unprotected); err != nil {
		return nil, errors.New("Parse error reading JWS")
	}

	// ACME v2 never uses values from the unprotected JWS header. Reject JWS that
	// include unprotected headers.
	if unprotected.Header != nil {
		return nil, errors.New(
			"JWS \"header\" field not allowed. All headers must be in \"protected\" field")
	}

	// ACME v2 never uses the "signatures" array of JSON serialized JWS, just the
	// mandatory "signature" field. Reject JWS that include the "signatures" array.
	if len(unprotected.Signatures) > 0 {
		return nil, errors.New(
			"JWS \"signatures\" field not allowed. Only the \"signature\" field should contain a signature")
	}

	parsedJWS, err := jose.ParseSigned(body)
	if err != nil {
		return nil, errors.New("Parse error reading JWS")
	}

	if len(parsedJWS.Signatures) > 1 {
		return nil, errors.New("Too many signatures in POST body")
	}

	if len(parsedJWS.Signatures) == 0 {
		return nil, errors.New("POST JWS not signed")
	}
	return parsedJWS, nil
}

// extractJWK returns a JSONWebKey embedded in a JWS header.
func (wfe *WebFrontEndImpl) extractJWK(_ *http.Request, jws *jose.JSONWebSignature) (*jose.JSONWebKey, *acme.ProblemDetails) {
	header := jws.Signatures[0].Header
	key := header.JSONWebKey
	if key == nil {
		return nil, acme.MalformedProblem("No JWK in JWS header")
	}
	if !key.Valid() {
		return nil, acme.MalformedProblem("Invalid JWK in JWS header")
	}
	if header.KeyID != "" {
		return nil, acme.MalformedProblem("jwk and kid header fields are mutually exclusive.")
	}
	return key, nil
}

// lookupJWK returns a JSONWebKey referenced by the "kid" (key id) field in a JWS header.
func (wfe *WebFrontEndImpl) lookupJWK(request *http.Request, jws *jose.JSONWebSignature) (*jose.JSONWebKey, *acme.ProblemDetails) {
	header := jws.Signatures[0].Header
	accountURL := header.KeyID
	prefix := wfe.relativeEndpoint(request, acctPath)
	accountID := strings.TrimPrefix(accountURL, prefix)
	if accountID == "" {
		return nil, acme.MalformedProblem("No key ID (kid) in JWS header")
	}
	account := wfe.db.GetAccountByID(accountID)
	if account == nil {
		return nil, acme.AccountDoesNotExistProblem(fmt.Sprintf(
			"Account %s not found.", accountURL))
	}
	if header.JSONWebKey != nil {
		return nil, acme.MalformedProblem("jwk and kid header fields are mutually exclusive.")
	}
	return account.Key, nil
}

// keyExtractor is a function that returns a JSONWebKey based on input from a
// user-provided JSONWebSignature, for instance by extracting it from the input,
// or by looking it up in a database based on the input.
type keyExtractor func(*http.Request, *jose.JSONWebSignature) (*jose.JSONWebKey, *acme.ProblemDetails)

// NOTE: Unlike `verifyPOST` from the Boulder WFE this version does not
// presently handle the `regCheck` parameter or do any lookups for existing
// accounts.
func (wfe *WebFrontEndImpl) verifyPOST(
	ctx context.Context,
	logEvent *requestEvent,
	request *http.Request,
	kx keyExtractor) ([]byte, *jose.JSONWebKey, *acme.ProblemDetails) {

	if _, present := request.Header["Content-Length"]; !present {
		return nil, nil, acme.MalformedProblem("missing Content-Length header on POST")
	}

	// Per 6.4.1  "Replay-Nonce" clients should not send a Replay-Nonce header in
	// the HTTP request, it needs to be part of the signed JWS request body
	if _, present := request.Header["Replay-Nonce"]; present {
		return nil, nil, acme.MalformedProblem("HTTP requests should NOT contain Replay-Nonce header. Use JWS nonce field")
	}

	if request.Body == nil {
		return nil, nil, acme.MalformedProblem("no body on POST")
	}

	bodyBytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return nil, nil, acme.InternalErrorProblem("unable to read request body")
	}

	body := string(bodyBytes)
	parsedJWS, err := wfe.parseJWS(body)
	if err != nil {
		return nil, nil, acme.MalformedProblem(err.Error())
	}

	pubKey, prob := kx(request, parsedJWS)
	if prob != nil {
		return nil, nil, prob
	}

	// TODO(@cpu): `checkAlgorithm()`

	payload, err := parsedJWS.Verify(pubKey)
	if err != nil {
		return nil, nil, acme.MalformedProblem("JWS verification error")
	}

	nonce := parsedJWS.Signatures[0].Header.Nonce
	if len(nonce) == 0 {
		return nil, nil, acme.BadNonceProblem("JWS has no anti-replay nonce")
	}

	// Roll a random number between 0 and 100.
	nonceRoll := rand.Intn(100)
	// If the nonce is not valid OR if the nonceRoll was less than the
	// nonceErrPercent, fail with an error
	if !wfe.nonce.validNonce(nonce) || nonceRoll < wfe.nonceErrPercent {
		return nil, nil, acme.BadNonceProblem(fmt.Sprintf(
			"JWS has an invalid anti-replay nonce: %s", nonce))
	}

	headerURL, ok := parsedJWS.Signatures[0].Header.ExtraHeaders[jose.HeaderKey("url")].(string)
	if !ok || len(headerURL) == 0 {
		return nil, nil, acme.MalformedProblem("JWS header parameter 'url' required.")
	}
	expectedURL := url.URL{
		// NOTE(@cpu): ACME **REQUIRES** HTTPS and Pebble is hardcoded to offer the
		// API over HTTPS.
		Scheme: "https",
		Host:   request.Host,
		Path:   request.RequestURI,
	}
	if expectedURL.String() != headerURL {
		return nil, nil, acme.MalformedProblem(fmt.Sprintf(
			"JWS header parameter 'url' incorrect. Expected %q, got %q",
			expectedURL.String(), headerURL))
	}

	return []byte(payload), pubKey, nil
}

// isASCII determines if every character in a string is encoded in
// the ASCII character set.
func isASCII(str string) bool {
	for _, r := range str {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func (wfe *WebFrontEndImpl) verifyContacts(acct acme.Account) *acme.ProblemDetails {
	contacts := acct.Contact

	// Providing no Contacts is perfectly acceptable
	if contacts == nil || len(contacts) == 0 {
		return nil
	}

	if len(contacts) > maxContactsPerAcct {
		return acme.MalformedProblem(fmt.Sprintf(
			"too many contacts provided: %d > %d", len(contacts), maxContactsPerAcct))
	}

	for _, c := range contacts {
		parsed, err := url.Parse(c)
		if err != nil {
			return acme.InvalidContactProblem(fmt.Sprintf("contact %q is invalid", c))
		}
		if parsed.Scheme != "mailto" {
			return acme.UnsupportedContactProblem(fmt.Sprintf(
				"contact method %q is not supported", parsed.Scheme))
		}
		email := parsed.Opaque
		// An empty or ommitted Contact array should be used instead of an empty contact
		if email == "" {
			return acme.InvalidContactProblem("empty contact email")
		}
		if !isASCII(email) {
			return acme.InvalidContactProblem(fmt.Sprintf(
				"contact email %q contains non-ASCII characters", email))
		}
		// NOTE(@cpu): ParseAddress may allow invalid emails since it supports RFC 5322
		// display names. This is sufficient for Pebble because we don't intend to
		// use the emails for anything and check this as a best effort for client
		// developers to test invalid contact problems.
		_, err = mail.ParseAddress(email)
		if err != nil {
			return acme.InvalidContactProblem(fmt.Sprintf(
				"contact email %q is invalid", email))
		}
	}

	return nil
}

func (wfe *WebFrontEndImpl) NewAccount(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	// We use extractJWK rather than lookupJWK here because the account is not yet
	// created, so the user provides the full key in a JWS header rather than
	// referring to an existing key.
	body, key, prob := wfe.verifyPOST(ctx, logEvent, request, wfe.extractJWK)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// newAcctReq is the ACME account information submitted by the client
	var newAcctReq struct {
		Contact            []string `json:"contact"`
		ToSAgreed          bool     `json:"termsOfServiceAgreed"`
		OnlyReturnExisting bool     `json:"onlyReturnExisting"`
	}
	err := json.Unmarshal(body, &newAcctReq)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem("Error unmarshaling body JSON"), response)
		return
	}

	keyID, err := keyToID(key)
	if err != nil {
		wfe.sendError(acme.MalformedProblem(err.Error()), response)
		return
	}

	// Lookup existing account to exit early if it exists
	// NOTE: We don't use wfe.getAccountByKey here because we want to treat a
	//       "missing" account as a non-error
	existingAcct := wfe.db.GetAccountByID(keyID)
	if existingAcct != nil {
		// If there is an existing account then return a Location header pointing to
		// the account and a 200 OK response
		acctURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", acctPath, existingAcct.ID))
		response.Header().Set("Location", acctURL)
		_ = wfe.writeJsonResponse(response, http.StatusOK, nil)
		return
	} else if existingAcct == nil && newAcctReq.OnlyReturnExisting {
		// If there *isn't* an existing account and the created account request
		// contained OnlyReturnExisting then this is an error - return now before
		// creating a new account with the key
		wfe.sendError(acme.AccountDoesNotExistProblem(
			"unable to find existing account for only-return-existing request"), response)
		return
	}

	if newAcctReq.ToSAgreed == false {
		response.Header().Add("Link", link(ToSURL, "terms-of-service"))
		wfe.sendError(
			acme.AgreementRequiredProblem(
				"Provided account did not agree to the terms of service"),
			response)
		return
	}

	// Create a new account object with the provided contact
	newAcct := core.Account{
		Account: acme.Account{
			Contact: newAcctReq.Contact,
			// New accounts are valid to start.
			Status: acme.StatusValid,
		},
		Key: key,
		ID:  keyID,
	}

	// Verify that the contact information provided is supported & valid
	prob = wfe.verifyContacts(newAcct.Account)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	count, err := wfe.db.AddAccount(&newAcct)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error saving account"), response)
		return
	}
	wfe.log.Printf("There are now %d accounts in memory\n", count)

	acctURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", acctPath, newAcct.ID))

	response.Header().Add("Location", acctURL)
	err = wfe.writeJsonResponse(response, http.StatusCreated, newAcct)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling account"), response)
		return
	}
}

func (wfe *WebFrontEndImpl) verifyOrder(order *core.Order, reg *core.Account) *acme.ProblemDetails {
	// Lock the order for reading
	order.RLock()
	defer order.RUnlock()

	// Shouldn't happen - defensive check
	if order == nil {
		return acme.InternalErrorProblem("Order is nil")
	}
	if reg == nil {
		return acme.InternalErrorProblem("Account is nil")
	}
	idents := order.Identifiers
	if len(idents) == 0 {
		return acme.MalformedProblem("Order did not specify any identifiers")
	}
	// Check that all of the identifiers in the new-order are DNS type
	for _, ident := range idents {
		if ident.Type != acme.IdentifierDNS {
			return acme.MalformedProblem(fmt.Sprintf(
				"Order included non-DNS type identifier: type %q, value %q",
				ident.Type, ident.Value))
		}

		// TODO(@cpu): We _very lightly_ validate the DNS identifiers in an order
		// compared to Boulder's full-fledged policy authority. We should consider
		// porting more of this logic to Pebble to let ACME clients test error
		// handling for policy rejection errors.
		rawDomain := ident.Value
		// If there is a wildcard character in the ident value there should be only
		// *one* instance
		if strings.Count(rawDomain, "*") > 1 {
			return acme.MalformedProblem(fmt.Sprintf(
				"Order included DNS type identifier with illegal wildcard value: "+
					"too many wildcards %q",
				rawDomain))
		} else if strings.Count(rawDomain, "*") == 1 {
			// If there is one wildcard character it should be the only character in
			// the leftmost label.
			if !strings.HasPrefix(rawDomain, "*.") {
				return acme.MalformedProblem(fmt.Sprintf(
					"Order included DNS type identifier with illegal wildcard value: "+
						"wildcard isn't leftmost prefix %q",
					rawDomain))
			}
		}
	}
	return nil
}

// makeAuthorizations populates an order with new authz's. The request parameter
// is required to make the authz URL's absolute based on the request host
func (wfe *WebFrontEndImpl) makeAuthorizations(order *core.Order, request *http.Request) error {
	var auths []string
	var authObs []*core.Authorization

	// Lock the order for reading
	order.RLock()
	// Create one authz for each name in the order's parsed CSR
	for _, name := range order.Names {
		now := wfe.clk.Now().UTC()
		expires := now.Add(pendingAuthzExpire)
		ident := acme.Identifier{
			Type:  acme.IdentifierDNS,
			Value: name,
		}
		authz := &core.Authorization{
			ID:          newToken(),
			ExpiresDate: expires,
			Order:       order,
			Authorization: acme.Authorization{
				Status:     acme.StatusPending,
				Identifier: ident,
				Expires:    expires.UTC().Format(time.RFC3339),
			},
		}
		authz.URL = wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", authzPath, authz.ID))
		// Create the challenges for this authz
		err := wfe.makeChallenges(authz, request)
		if err != nil {
			return err
		}
		// Save the authorization in memory
		count, err := wfe.db.AddAuthorization(authz)
		if err != nil {
			return err
		}
		wfe.log.Printf("There are now %d authorizations in the db\n", count)
		authzURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", authzPath, authz.ID))
		auths = append(auths, authzURL)
		authObs = append(authObs, authz)
	}
	// Unlock the order from reading
	order.RUnlock()

	// Lock the order for writing & update the order's authorizations
	order.Lock()
	order.Authorizations = auths
	order.AuthorizationObjects = authObs
	order.Unlock()
	return nil
}

func (wfe *WebFrontEndImpl) makeChallenge(
	chalType string,
	authz *core.Authorization,
	request *http.Request) (*core.Challenge, error) {
	// Create a new challenge of the requested type
	id := newToken()
	chal := &core.Challenge{
		ID: id,
		Challenge: acme.Challenge{
			Type:   chalType,
			Token:  newToken(),
			URL:    wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", challengePath, id)),
			Status: acme.StatusPending,
		},
		Authz: authz,
	}

	// Add it to the in-memory database
	_, err := wfe.db.AddChallenge(chal)
	if err != nil {
		return nil, err
	}
	return chal, nil
}

// makeChallenges populates an authz with new challenges. The request parameter
// is required to make the challenge URL's absolute based on the request host
func (wfe *WebFrontEndImpl) makeChallenges(authz *core.Authorization, request *http.Request) error {
	var chals []*core.Challenge

	// Authorizations for a wildcard identifier only get a DNS-01 challenges to
	// match Boulder/Let's Encrypt wildcard issuance policy
	if strings.HasPrefix(authz.Identifier.Value, "*.") {
		chal, err := wfe.makeChallenge(acme.ChallengeDNS01, authz, request)
		if err != nil {
			return err
		}
		chals = []*core.Challenge{chal}
	} else {
		// Non-wildcard authorizations get all of the enabled challenge types
		enabledChallenges := []string{acme.ChallengeHTTP01, acme.ChallengeTLSSNI02, acme.ChallengeDNS01}
		for _, chalType := range enabledChallenges {
			chal, err := wfe.makeChallenge(chalType, authz, request)
			if err != nil {
				return err
			}
			chals = append(chals, chal)
		}
	}

	// Lock the authorization for writing to update the challenges
	authz.Lock()
	authz.Challenges = nil
	for _, c := range chals {
		authz.Challenges = append(authz.Challenges, &c.Challenge)
	}
	authz.Unlock()
	return nil
}

// NewOrder creates a new Order request and populates its authorizations
func (wfe *WebFrontEndImpl) NewOrder(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	body, key, prob := wfe.verifyPOST(ctx, logEvent, request, wfe.lookupJWK)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	existingReg, prob := wfe.getAcctByKey(key)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// Unpack the order request body
	var newOrder acme.Order
	err := json.Unmarshal(body, &newOrder)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem("Error unmarshaling body JSON: "+err.Error()), response)
		return
	}

	expires := time.Now().AddDate(0, 0, 1)
	order := &core.Order{
		ID:        newToken(),
		AccountID: existingReg.ID,
		Order: acme.Order{
			Status:  acme.StatusPending,
			Expires: expires.UTC().Format(time.RFC3339),
			// Only the Identifiers, NotBefore and NotAfter from the submitted order
			// are carried forward
			Identifiers: newOrder.Identifiers,
			NotBefore:   newOrder.NotBefore,
			NotAfter:    newOrder.NotAfter,
		},
		ExpiresDate: expires,
	}

	// Verify the details of the order before creating authorizations
	if err := wfe.verifyOrder(order, existingReg); err != nil {
		wfe.sendError(err, response)
		return
	}

	// Collect all of the DNS identifier values up into a []string
	var orderNames []string
	for _, ident := range order.Identifiers {
		orderNames = append(orderNames, ident.Value)
	}

	// Store the unique lower version of the names on the order object
	order.Names = uniqueLowerNames(orderNames)

	// Create the authorizations for the order
	err = wfe.makeAuthorizations(order, request)
	if err != nil {
		wfe.sendError(
			acme.InternalErrorProblem("Error creating authorizations for order"), response)
		return
	}

	// Add the order to the in-memory DB
	count, err := wfe.db.AddOrder(order)
	if err != nil {
		wfe.sendError(
			acme.InternalErrorProblem("Error saving order"), response)
		return
	}
	wfe.log.Printf("Added order %q to the db\n", order.ID)
	wfe.log.Printf("There are now %d orders in the db\n", count)

	// Populate a finalization URL for this order
	order.Finalize = wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", orderFinalizePath, order.ID))

	orderURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", orderPath, order.ID))
	response.Header().Add("Location", orderURL)
	err = wfe.writeJsonResponse(response, http.StatusCreated, order.Order)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling order"), response)
		return
	}
}

// orderForDisplay preps a *core.Order for display by populating some fields
// based on the http.request provided and returning a *acme.Order ready to be
// rendered to JSON for display to an API client.
func (wfe *WebFrontEndImpl) orderForDisplay(
	order *core.Order,
	request *http.Request) acme.Order {
	// Lock the order for reading
	order.RLock()
	defer order.RUnlock()

	// Populate a finalization URL for this order
	order.Finalize = wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", orderFinalizePath, order.ID))

	// If the order has a cert ID then set the certificate URL by constructing
	// a relative path based on the HTTP request & the cert ID
	if order.CertificateObject != nil {
		order.Certificate = wfe.relativeEndpoint(
			request,
			certPath+order.CertificateObject.ID)
	}

	// Return only the initial OrderRequest not the internal object
	return order.Order
}

// Order retrieves the details of an existing order
func (wfe *WebFrontEndImpl) Order(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	orderID := strings.TrimPrefix(request.URL.Path, orderPath)
	order := wfe.db.GetOrderByID(orderID)
	if order == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}

	// Prepare the order for display as JSON
	orderReq := wfe.orderForDisplay(order, request)
	err := wfe.writeJsonResponse(response, http.StatusOK, orderReq)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling order"), response)
		return
	}
}

func (wfe *WebFrontEndImpl) FinalizeOrder(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	// Verify the POST request
	body, key, prob := wfe.verifyPOST(ctx, logEvent, request, wfe.lookupJWK)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// Find the account corresponding to the key that authenticated the POST request
	existingAcct, prob := wfe.getAcctByKey(key)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// Find the order specified by the order ID
	orderID := strings.TrimPrefix(request.URL.Path, orderFinalizePath)
	existingOrder := wfe.db.GetOrderByID(orderID)
	if existingOrder == nil {
		response.WriteHeader(http.StatusNotFound)
		wfe.sendError(acme.NotFoundProblem(fmt.Sprintf(
			"No order %q found for account ID %q", orderID, existingAcct.ID)), response)
		return
	}

	// Lock the order for reading the properties we need to check
	existingOrder.RLock()
	orderAccountID := existingOrder.AccountID
	orderStatus := existingOrder.Status
	orderExpires := existingOrder.ExpiresDate
	orderNames := existingOrder.Names
	// And then immediately unlock it again - we don't defer() here because
	// `maybeIssue` will also acquire a read lock and we call that before
	// returning
	existingOrder.RUnlock()

	// If the order doesn't belong to the account that authenticted the POST
	// request then pretend it doesn't exist.
	if orderAccountID != existingAcct.ID {
		response.WriteHeader(http.StatusNotFound)
		wfe.sendError(acme.NotFoundProblem(fmt.Sprintf(
			"No order %q found for account ID %q", orderID, existingAcct.ID)), response)
		return
	}

	// The existing order must be in a pending status to finalize it
	if orderStatus != acme.StatusPending {
		wfe.sendError(acme.MalformedProblem(fmt.Sprintf(
			"Order's status (%q) was not pending", orderStatus)), response)
		return
	}

	// The existing order must not be expired
	if orderExpires.Before(wfe.clk.Now()) {
		wfe.sendError(acme.NotFoundProblem(fmt.Sprintf(
			"Order %q expired %s", orderID, orderExpires)), response)
		return
	}

	// The finalize POST body is expected to be the bytes from a base64 raw url
	// encoded CSR
	var finalizeMessage struct {
		CSR string
	}
	err := json.Unmarshal(body, &finalizeMessage)
	if err != nil {
		wfe.sendError(acme.MalformedProblem(fmt.Sprintf(
			"Error unmarshaling finalize order request body: %s", err.Error())), response)
		return
	}

	csrBytes, err := base64.RawURLEncoding.DecodeString(finalizeMessage.CSR)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem("Error decoding Base64url-encoded CSR: "+err.Error()), response)
		return
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem("Error parsing Base64url-encoded CSR: "+err.Error()), response)
		return
	}

	// Check that the CSR has the same number of names as the initial order contained
	csrNames := uniqueLowerNames(parsedCSR.DNSNames)
	if len(csrNames) != len(orderNames) {
		wfe.sendError(acme.UnauthorizedProblem(
			"Order includes different number of names than CSR specifieds"), response)
		return
	}

	// Check that the CSR's names match the order names exactly
	for i, name := range orderNames {
		if name != csrNames[i] {
			wfe.sendError(acme.UnauthorizedProblem(
				fmt.Sprintf("CSR is missing Order domain %q", name)), response)
			return
		}
	}

	// Lock and update the order with the parsed CSR.
	existingOrder.Lock()
	existingOrder.ParsedCSR = parsedCSR
	existingOrder.Unlock()

	// Check whether the order is ready to issue, if it isn't, return a problem
	prob = wfe.maybeIssue(existingOrder)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// Prepare the order for display as JSON
	orderReq := wfe.orderForDisplay(existingOrder, request)
	orderURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", orderPath, existingOrder.ID))
	response.Header().Add("Location", orderURL)
	err = wfe.writeJsonResponse(response, http.StatusOK, orderReq)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling order"), response)
		return
	}
}

func (wfe *WebFrontEndImpl) maybeIssue(order *core.Order) *acme.ProblemDetails {
	// Lock the order for reading to check whether all authorizations are valid
	order.RLock()
	authzs := order.AuthorizationObjects
	orderID := order.ID
	order.RUnlock()
	for _, authz := range authzs {
		// Lock the authorization for reading to check its status
		authz.RLock()
		authzStatus := authz.Status
		authzExpires := authz.ExpiresDate
		ident := authz.Identifier
		authz.RUnlock()
		// If any of the authorizations are invalid the order isn't ready to issue
		if authzStatus != acme.StatusValid {
			return acme.UnauthorizedProblem(fmt.Sprintf(
				"Authorization for %q is not status valid", ident.Value))
		}
		// If any of the authorizations are expired the order isn't ready to issue
		if authzExpires.Before(wfe.clk.Now()) {
			return acme.UnauthorizedProblem(fmt.Sprintf(
				"Authorization for %q expired %q", ident.Value, authzExpires))
		}
	}
	// All the authorizations are valid, ask the CA to complete the order in
	// a separate goroutine. CompleteOrder will transition the order status to
	// pending.
	wfe.log.Printf("Order %s is fully authorized. Processing finalization", orderID)
	go wfe.ca.CompleteOrder(order)
	return nil
}

// prepAuthorizationForDisplay prepares the provided acme.Authorization for
// display to an ACME client.
func prepAuthorizationForDisplay(authz acme.Authorization) *acme.Authorization {
	identVal := authz.Identifier.Value
	// If the authorization identifier has a wildcard in the value, remove it and
	// set the Wildcard field to true
	if strings.HasPrefix(identVal, "*.") {
		authz.Identifier.Value = strings.TrimPrefix(identVal, "*.")
		authz.Wildcard = true
	}
	return &authz
}

func (wfe *WebFrontEndImpl) Authz(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	authzID := strings.TrimPrefix(request.URL.Path, authzPath)
	authz := wfe.db.GetAuthorizationByID(authzID)
	if authz == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}

	err := wfe.writeJsonResponse(
		response,
		http.StatusOK,
		prepAuthorizationForDisplay(authz.Authorization))
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling authz"), response)
		return
	}
}

func (wfe *WebFrontEndImpl) Challenge(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	if request.Method == "POST" {
		wfe.updateChallenge(ctx, logEvent, response, request)
		return
	}

	wfe.getChallenge(ctx, logEvent, response, request)
}

func (wfe *WebFrontEndImpl) getChallenge(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	chalID := strings.TrimPrefix(request.URL.Path, challengePath)
	chal := wfe.db.GetChallengeByID(chalID)
	if chal == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}

	// Lock the challenge for reading in order to write the response
	chal.RLock()
	defer chal.RUnlock()

	err := wfe.writeJsonResponse(response, http.StatusOK, chal.Challenge)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling challenge"), response)
		return
	}
}

// getAcctByKey finds a account by key or returns a problem pointer if an
// existing account can't be found or the key is invalid.
func (wfe *WebFrontEndImpl) getAcctByKey(key crypto.PublicKey) (*core.Account, *acme.ProblemDetails) {
	// Compute the account ID for the signer's key
	regID, err := keyToID(key)
	if err != nil {
		wfe.log.Printf("keyToID err: %s\n", err.Error())
		return nil, acme.MalformedProblem("Error computing key digest")
	}

	// Find the existing account object for that key ID
	var existingAcct *core.Account
	if existingAcct = wfe.db.GetAccountByID(regID); existingAcct == nil {
		return nil, acme.AccountDoesNotExistProblem(
			"URL in JWS 'kid' field does not correspond to an account")
	}
	return existingAcct, nil
}

func (wfe *WebFrontEndImpl) validateChallengeUpdate(
	chal *core.Challenge,
	update *acme.Challenge,
	acct *core.Account) (*core.Authorization, *acme.ProblemDetails) {
	// Lock the challenge for reading to do validation
	chal.RLock()
	defer chal.RUnlock()

	// Check that the existing challenge is Pending
	if chal.Status != acme.StatusPending {
		return nil, acme.MalformedProblem(
			fmt.Sprintf("Cannot update challenge with status %s, only status %s",
				chal.Status, acme.StatusPending))
	}

	// Calculate the expected key authorization for the owning account's key
	expectedKeyAuth := chal.ExpectedKeyAuthorization(acct.Key)

	// Validate the expected key auth matches the provided key auth
	if expectedKeyAuth != update.KeyAuthorization {
		return nil, acme.MalformedProblem(
			fmt.Sprintf("Incorrect key authorization: %q",
				update.KeyAuthorization))
	}

	return chal.Authz, nil
}

// validateAuthzForChallenge checks an authz is:
// 1) for a supported identifier type
// 2) not expired
// 3) associated to an order
// The associated order is returned when no problems are found to avoid needing
// another RLock() for the caller to get the order pointer later.
func (wfe *WebFrontEndImpl) validateAuthzForChallenge(authz *core.Authorization) (*core.Order, *acme.ProblemDetails) {
	// Lock the authz for reading
	authz.RLock()
	defer authz.RUnlock()

	ident := authz.Identifier
	if ident.Type != acme.IdentifierDNS {
		return nil, acme.MalformedProblem(
			fmt.Sprintf("Authorization identifier was type %s, only %s is supported",
				ident.Type, acme.IdentifierDNS))
	}

	now := wfe.clk.Now()
	if now.After(authz.ExpiresDate) {
		return nil, acme.MalformedProblem(
			fmt.Sprintf("Authorization expired %s",
				authz.ExpiresDate.Format(time.RFC3339)))
	}

	existingOrder := authz.Order
	if existingOrder == nil {
		return nil, acme.InternalErrorProblem("authz missing associated order")
	}

	return existingOrder, nil
}

func (wfe *WebFrontEndImpl) updateChallenge(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	body, key, prob := wfe.verifyPOST(ctx, logEvent, request, wfe.lookupJWK)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	existingAcct, prob := wfe.getAcctByKey(key)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	var chalResp acme.Challenge
	err := json.Unmarshal(body, &chalResp)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem("Error unmarshaling body JSON"), response)
		return
	}

	chalID := strings.TrimPrefix(request.URL.Path, challengePath)
	existingChal := wfe.db.GetChallengeByID(chalID)
	if existingChal == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}

	authz, prob := wfe.validateChallengeUpdate(existingChal, &chalResp, existingAcct)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}
	if authz == nil {
		wfe.sendError(
			acme.InternalErrorProblem("challenge missing associated authz"), response)
		return
	}

	existingOrder, prob := wfe.validateAuthzForChallenge(authz)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// Lock the order for reading to check the expiry date
	existingOrder.RLock()
	now := wfe.clk.Now()
	if now.After(existingOrder.ExpiresDate) {
		wfe.sendError(
			acme.MalformedProblem(fmt.Sprintf("order expired %s %s",
				existingOrder.ExpiresDate.Format(time.RFC3339))), response)
		return
	}
	existingOrder.RUnlock()

	// Lock the authorization to get the identifier value
	authz.RLock()
	ident := authz.Identifier.Value
	authz.RUnlock()

	// If the identifier value is for a wildcard domain then strip the wildcard
	// prefix before dispatching the validation to ensure the base domain is
	// validated.
	if strings.HasPrefix(ident, "*.") {
		ident = strings.TrimPrefix(ident, "*.")
	}

	// Submit a validation job to the VA, this will be processed asynchronously
	wfe.va.ValidateChallenge(ident, existingChal, existingAcct)

	// Lock the challenge for reading in order to write the response
	existingChal.RLock()
	defer existingChal.RUnlock()
	response.Header().Add("Link", link(existingChal.Authz.URL, "up"))
	err = wfe.writeJsonResponse(response, http.StatusOK, existingChal.Challenge)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling challenge"), response)
		return
	}
}

func (wfe *WebFrontEndImpl) Certificate(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	serial := strings.TrimPrefix(request.URL.Path, certPath)
	cert := wfe.db.GetCertificateByID(serial)
	if cert == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}

	response.Header().Set("Content-Type", "application/pem-certificate-chain; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(cert.Chain())
}

func (wfe *WebFrontEndImpl) writeJsonResponse(response http.ResponseWriter, status int, v interface{}) error {
	jsonReply, err := marshalIndent(v)
	if err != nil {
		return err // All callers are responsible for handling this error
	}

	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)

	// Don't worry about returning an error from Write() because the caller will
	// never handle it.
	_, _ = response.Write(jsonReply)
	return nil
}

func addNoCacheHeader(response http.ResponseWriter) {
	response.Header().Add("Cache-Control", "public, max-age=0, no-cache")
}

func marshalIndent(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "   ")
}

func link(url, relation string) string {
	return fmt.Sprintf("<%s>;rel=\"%s\"", url, relation)
}

// uniqueLowerNames returns the set of all unique names in the input after all
// of them are lowercased. The returned names will be in their lowercased form
// and sorted alphabetically. See Boulder `core/util.go UniqueLowerNames`.
func uniqueLowerNames(names []string) []string {
	nameMap := make(map[string]int, len(names))
	for _, name := range names {
		nameMap[strings.ToLower(name)] = 1
	}
	unique := make([]string, 0, len(nameMap))
	for name := range nameMap {
		unique = append(unique, name)
	}
	sort.Strings(unique)
	return unique
}
