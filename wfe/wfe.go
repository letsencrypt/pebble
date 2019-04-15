package wfe

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/square/go-jose.v2"

	"github.com/letsencrypt/pebble/acme"
	"github.com/letsencrypt/pebble/ca"
	"github.com/letsencrypt/pebble/core"
	"github.com/letsencrypt/pebble/db"
	"github.com/letsencrypt/pebble/va"
)

const (
	// Note: We deliberately pick endpoint paths that differ from Boulder to
	// exercise clients processing of the /directory response
	// We export the DirectoryPath and RootCertPath so that the pebble binary can reference it
	DirectoryPath     = "/dir"
	RootCertPath      = "/root"
	noncePath         = "/nonce-plz"
	newAccountPath    = "/sign-me-up"
	acctPath          = "/my-account/"
	newOrderPath      = "/order-plz"
	orderPath         = "/my-order/"
	orderFinalizePath = "/finalize-order/"
	authzPath         = "/authZ/"
	challengePath     = "/chalZ/"
	certPath          = "/certZ/"
	revokeCertPath    = "/revoke-cert"
	keyRolloverPath   = "/rollover-account-key"

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
	//   PEBBLE_WFE_NONCEREJECT=15 pebble
	badNonceEnvVar = "PEBBLE_WFE_NONCEREJECT"

	// By default when no PEBBLE_WFE_NONCEREJECT is set, what percentage of good
	// nonces are rejected?
	defaultNonceReject = 5

	// POST requests with a JWS body must have the following Content-Type header
	expectedJWSContentType = "application/jose+json"

	// RFC 1034 says DNS labels have a max of 63 octets, and names have a max of 255
	// octets: https://tools.ietf.org/html/rfc1035#page-10. Since two of those octets
	// are taken up by the leading length byte and the trailing root period the actual
	// max length becomes 253.
	maxDNSIdentifierLength = 253

	// Invalid revocation reason codes.
	// The full list of codes can be found in Section 8.5.3.1 of ITU-T X.509
	// http://www.itu.int/rec/T-REC-X.509-201210-I/en
	unusedRevocationReason       = 7
	aACompromiseRevocationReason = 10
)

type wfeHandlerFunc func(context.Context, http.ResponseWriter, *http.Request)

func (f wfeHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := context.TODO()
	f(ctx, w, r)
}

type wfeHandler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

type topHandler struct {
	wfe wfeHandler
}

func (th *topHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	th.wfe.ServeHTTP(w, r)
}

type WebFrontEndImpl struct {
	log             *log.Logger
	db              *db.MemoryStore
	nonce           *nonceMap
	nonceErrPercent int
	va              *va.VAImpl
	ca              *ca.CAImpl
	strict          bool
}

const ToSURL = "data:text/plain,Do%20what%20thou%20wilt"

func New(
	log *log.Logger,
	db *db.MemoryStore,
	va *va.VAImpl,
	ca *ca.CAImpl,
	strict bool) WebFrontEndImpl {

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
		va:              va,
		ca:              ca,
		strict:          strict,
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
			wfe: wfeHandlerFunc(func(ctx context.Context, response http.ResponseWriter, request *http.Request) {
				// Modern ACME only sends a Replay-Nonce in responses to GET/HEAD
				// requests to the dedicated newNonce endpoint, or in replies to POST
				// requests that consumed a nonce.
				if request.Method == "POST" || pattern == noncePath {
					response.Header().Set("Replay-Nonce", wfe.nonce.createNonce())
				}

				// Per section 7.1 "Resources":
				//   The "index" link relation is present on all resources other than the
				//   directory and indicates the URL of the directory.
				if pattern != DirectoryPath {
					directoryURL := wfe.relativeEndpoint(request, DirectoryPath)
					response.Header().Add("Link", link(directoryURL, "index"))
				}

				addNoCacheHeader(response)

				if !methodsMap[request.Method] {
					response.Header().Set("Allow", methodsStr)
					wfe.sendError(acme.MethodNotAllowed(), response)
					return
				}

				wfe.log.Printf("%s %s -> calling handler()\n", request.Method, pattern)

				// TODO(@cpu): Configurable request timeout
				timeout := 1 * time.Minute
				ctx, cancel := context.WithTimeout(ctx, timeout)
				handler(ctx, response, request)
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
	_, _ = response.Write(problemDoc)
}

func (wfe *WebFrontEndImpl) RootCert(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request) {

	root := wfe.ca.GetRootCert()
	if root == nil {
		response.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	response.Header().Set("Content-Type", "application/pem-certificate-chain; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(root.PEM())
}

func (wfe *WebFrontEndImpl) Handler() http.Handler {
	m := http.NewServeMux()
	// GET only handlers
	wfe.HandleFunc(m, DirectoryPath, wfe.Directory, "GET")
	// Note for noncePath: "GET" also implies "HEAD"
	wfe.HandleFunc(m, noncePath, wfe.Nonce, "GET")
	wfe.HandleFunc(m, RootCertPath, wfe.RootCert, "GET")

	// POST only handlers
	wfe.HandleFunc(m, newAccountPath, wfe.NewAccount, "POST")
	wfe.HandleFunc(m, newOrderPath, wfe.NewOrder, "POST")
	wfe.HandleFunc(m, orderFinalizePath, wfe.FinalizeOrder, "POST")
	wfe.HandleFunc(m, acctPath, wfe.UpdateAccount, "POST")
	wfe.HandleFunc(m, keyRolloverPath, wfe.KeyRollover, "POST")
	wfe.HandleFunc(m, revokeCertPath, wfe.RevokeCert, "POST")
	wfe.HandleFunc(m, certPath, wfe.Certificate, "POST")
	wfe.HandleFunc(m, orderPath, wfe.Order, "POST")
	wfe.HandleFunc(m, authzPath, wfe.Authz, "POST")
	wfe.HandleFunc(m, challengePath, wfe.Challenge, "POST")

	return m
}

func (wfe *WebFrontEndImpl) Directory(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request) {

	directoryEndpoints := map[string]string{
		"newNonce":   noncePath,
		"newAccount": newAccountPath,
		"newOrder":   newOrderPath,
		"revokeCert": revokeCertPath,
		"keyChange":  keyRolloverPath,
	}

	response.Header().Set("Content-Type", "application/json; charset=utf-8")

	relDir, err := wfe.relativeDirectory(request, directoryEndpoints)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("unable to create directory"), response)
		return
	}

	_, _ = response.Write(relDir)
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
	// This should never happen since we are just marshaling known strings
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

	return (&url.URL{Scheme: proto, Host: host, Path: endpoint}).String()
}

func (wfe *WebFrontEndImpl) Nonce(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request) {
	statusCode := http.StatusNoContent
	// The ACME specification says GET requets should receive http.StatusNoContent
	// and HEAD requests should receive http.StatusOK.
	if request.Method == "HEAD" {
		statusCode = http.StatusOK
	}
	response.WriteHeader(statusCode)
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

// jwsAuthType represents whether a given POST request is authenticated using
// a JWS with an embedded JWK (new-account, possibly revoke-cert) or an
// embedded Key ID or an unsupported/unknown auth type.
type jwsAuthType int

const (
	embeddedJWK jwsAuthType = iota
	embeddedKeyID
	invalidAuthType
)

// checkJWSAuthType examines a JWS' protected headers to determine if
// the request being authenticated by the JWS is identified using an embedded
// JWK or an embedded key ID. If no signatures are present, or mutually
// exclusive authentication types are specified at the same time, a problem is
// returned.
func checkJWSAuthType(jws *jose.JSONWebSignature) (jwsAuthType, *acme.ProblemDetails) {
	// checkJWSAuthType is called after parseJWS() which defends against the
	// incorrect number of signatures.
	header := jws.Signatures[0].Header
	// There must not be a Key ID *and* an embedded JWK
	if header.KeyID != "" && header.JSONWebKey != nil {
		return invalidAuthType, acme.MalformedProblem("jwk and kid header fields are mutually exclusive")
	} else if header.KeyID != "" {
		return embeddedKeyID, nil
	} else if header.JSONWebKey != nil {
		return embeddedJWK, nil
	}
	return invalidAuthType, nil
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
	if !strings.HasPrefix(accountURL, prefix) {
		return nil, acme.MalformedProblem("Key ID (kid) in JWS header missing expected URL prefix")
	}
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

func (wfe *WebFrontEndImpl) validPOST(request *http.Request) *acme.ProblemDetails {
	// Section 6.2 says to reject JWS requests without the expected Content-Type
	// using a status code of http.UnsupportedMediaType
	if _, present := request.Header["Content-Type"]; !present {
		return acme.UnsupportedMediaTypeProblem(
			`missing Content-Type header on POST. ` +
				`Content-Type must be "application/jose+json"`)
	}
	if contentType := request.Header.Get("Content-Type"); contentType != expectedJWSContentType {
		return acme.UnsupportedMediaTypeProblem(
			`Invalid Content-Type header on POST. ` +
				`Content-Type must be "application/jose+json"`)
	}

	if _, present := request.Header["Content-Length"]; !present {
		return acme.MalformedProblem("missing Content-Length header on POST")
	}

	// Per 6.4.1  "Replay-Nonce" clients should not send a Replay-Nonce header in
	// the HTTP request, it needs to be part of the signed JWS request body
	if _, present := request.Header["Replay-Nonce"]; present {
		return acme.MalformedProblem("HTTP requests should NOT contain Replay-Nonce header. Use JWS nonce field")
	}

	// All POSTs must have a body
	if request.Body == nil {
		return acme.MalformedProblem("no body on POST")
	}

	return nil
}

func (wfe *WebFrontEndImpl) validPOSTAsGET(postData *authenticatedPOST) (*core.Account, *acme.ProblemDetails) {
	if postData == nil {
		return nil, acme.InternalErrorProblem("nil authenticated POST data")
	}

	if !postData.postAsGet {
		return nil, acme.MalformedProblem("POST-as-GET requests must have a nil body")
	}

	// All POST-as-GET requests are authenticated by an existing account
	account, prob := wfe.getAcctByKey(postData.jwk)
	if prob != nil {
		return nil, prob
	}

	return account, nil
}

// keyExtractor is a function that returns a JSONWebKey based on input from a
// user-provided JSONWebSignature, for instance by extracting it from the input,
// or by looking it up in a database based on the input.
type keyExtractor func(*http.Request, *jose.JSONWebSignature) (*jose.JSONWebKey, *acme.ProblemDetails)

type authenticatedPOST struct {
	postAsGet bool
	body      []byte
	url       string
	jwk       *jose.JSONWebKey
}

// NOTE: Unlike `verifyPOST` from the Boulder WFE this version does not
// presently handle the `regCheck` parameter or do any lookups for existing
// accounts.
func (wfe *WebFrontEndImpl) verifyPOST(
	request *http.Request,
	kx keyExtractor) (*authenticatedPOST, *acme.ProblemDetails) {

	if prob := wfe.validPOST(request); prob != nil {
		return nil, prob
	}

	bodyBytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return nil, acme.InternalErrorProblem("unable to read request body")
	}

	body := string(bodyBytes)
	parsedJWS, err := wfe.parseJWS(body)
	if err != nil {
		return nil, acme.MalformedProblem(err.Error())
	}

	pubKey, prob := kx(request, parsedJWS)
	if prob != nil {
		return nil, prob
	}

	result, prob := wfe.verifyJWS(pubKey, parsedJWS, request)
	if prob != nil {
		return nil, prob
	}

	return result, nil
}

// verifyJWSSignatureAndAlgorithm verifies the pubkey and JWS algorithms are
// acceptable and that the JWS verifies with the provided pubkey.
func (wfe *WebFrontEndImpl) verifyJWSSignatureAndAlgorithm(
	pubKey *jose.JSONWebKey,
	parsedJWS *jose.JSONWebSignature) ([]byte, *acme.ProblemDetails) {
	if prob := checkAlgorithm(pubKey, parsedJWS); prob != nil {
		return nil, prob
	}

	payload, err := parsedJWS.Verify(pubKey)
	if err != nil {
		return nil, acme.MalformedProblem(fmt.Sprintf("JWS verification error: %s", err))
	}
	return payload, nil
}

// Extracts URL header parameter from parsed JWS.
// Second return value indicates whether header was found.
func (wfe *WebFrontEndImpl) extractJWSURL(
	parsedJWS *jose.JSONWebSignature) (string, bool) {
	headerURL, ok := parsedJWS.Signatures[0].Header.ExtraHeaders[jose.HeaderKey("url")].(string)
	if !ok || len(headerURL) == 0 {
		return "", false
	}
	return headerURL, true
}

func (wfe *WebFrontEndImpl) verifyJWS(
	pubKey *jose.JSONWebKey,
	parsedJWS *jose.JSONWebSignature,
	request *http.Request) (*authenticatedPOST, *acme.ProblemDetails) {
	payload, prob := wfe.verifyJWSSignatureAndAlgorithm(pubKey, parsedJWS)
	if prob != nil {
		return nil, prob
	}

	headerURL, ok := wfe.extractJWSURL(parsedJWS)
	if !ok {
		return nil, acme.MalformedProblem("JWS header parameter 'url' required.")
	}

	nonce := parsedJWS.Signatures[0].Header.Nonce
	if len(nonce) == 0 {
		return nil, acme.BadNonceProblem("JWS has no anti-replay nonce")
	}

	// Roll a random number between 0 and 100.
	nonceRoll := rand.Intn(100)
	// If the nonce is not valid OR if the nonceRoll was less than the
	// nonceErrPercent, fail with an error
	if !wfe.nonce.validNonce(nonce) || nonceRoll < wfe.nonceErrPercent {
		return nil, acme.BadNonceProblem(fmt.Sprintf(
			"JWS has an invalid anti-replay nonce: %s", nonce))
	}

	expectedURL := url.URL{
		// NOTE(@cpu): ACME **REQUIRES** HTTPS and Pebble is hardcoded to offer the
		// API over HTTPS.
		Scheme: "https",
		Host:   request.Host,
		Path:   request.RequestURI,
	}
	if expectedURL.String() != headerURL {
		return nil, acme.MalformedProblem(fmt.Sprintf(
			"JWS header parameter 'url' incorrect. Expected %q, got %q",
			expectedURL.String(), headerURL))
	}

	return &authenticatedPOST{
		postAsGet: string(payload) == "",
		body:      payload,
		url:       headerURL,
		jwk:       pubKey}, nil
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
	if len(contacts) == 0 {
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
		// An empty or omitted Contact array should be used instead of an empty contact
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

func (wfe *WebFrontEndImpl) UpdateAccount(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request) {
	postData, prob := wfe.verifyPOST(request, wfe.lookupJWK)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// updateAcctReq is the ACME account information submitted by the client
	var updateAcctReq struct {
		Contact []string `json:"contact"`
		Status  string   `json:"status,omitempty"`
	}
	var existingAcct *core.Account
	if postData.postAsGet {
		existingAcct, prob = wfe.validPOSTAsGET(postData)
		if prob != nil {
			wfe.sendError(prob, response)
			return
		}
	} else {
		err := json.Unmarshal(postData.body, &updateAcctReq)
		if err != nil {
			wfe.sendError(
				acme.MalformedProblem("Error unmarshaling account update JSON body"), response)
			return
		}
		existingAcct, prob = wfe.getAcctByKey(postData.jwk)
		if prob != nil {
			wfe.sendError(prob, response)
			return
		}
	}

	// if this update contains no contacts or deactivated status,
	// simply return the existing account and return early.
	if updateAcctReq.Contact == nil && updateAcctReq.Status != acme.StatusDeactivated {
		if !postData.postAsGet {
			wfe.sendError(acme.MalformedProblem("Use POST-as-GET to retrieve account data instead of doing an empty update"), response)
			return
		}
		err := wfe.writeJSONResponse(response, http.StatusOK, existingAcct)
		if err != nil {
			wfe.sendError(acme.InternalErrorProblem("Error marshalling account"), response)
			return
		}
		return
	}

	// Create a new account object with the existing data
	newAcct := &core.Account{
		Account: acme.Account{
			Contact: existingAcct.Contact,
			Status:  existingAcct.Status,
			Orders:  existingAcct.Orders,
		},
		Key: existingAcct.Key,
		ID:  existingAcct.ID,
	}

	switch {
	case updateAcctReq.Status == acme.StatusDeactivated:
		newAcct.Status = updateAcctReq.Status
	case updateAcctReq.Status != "" && updateAcctReq.Status != newAcct.Status:
		wfe.sendError(
			acme.MalformedProblem(fmt.Sprintf(
				"Invalid account status: %q", updateAcctReq.Status)), response)
		return
	case updateAcctReq.Contact != nil:
		newAcct.Contact = updateAcctReq.Contact
		// Verify that the contact information provided is supported & valid
		prob = wfe.verifyContacts(newAcct.Account)
		if prob != nil {
			wfe.sendError(prob, response)
			return
		}
	}

	err := wfe.db.UpdateAccountByID(existingAcct.ID, newAcct)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem("Error storing updated account"), response)
		return
	}

	err = wfe.writeJSONResponse(response, http.StatusOK, newAcct)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling account"), response)
		return
	}
}

func (wfe *WebFrontEndImpl) verifyKeyRollover(
	innerPayload []byte,
	existingAcct *core.Account,
	newKey *jose.JSONWebKey,
	request *http.Request) *acme.ProblemDetails {
	var innerContent struct {
		Account string
		OldKey  jose.JSONWebKey
	}
	err := json.Unmarshal(innerPayload, &innerContent)
	if err != nil {
		return acme.MalformedProblem("Error unmarshaling key roll-over inner JWS body")
	}

	// Check account ID
	prefix := wfe.relativeEndpoint(request, acctPath)
	if !strings.HasPrefix(innerContent.Account, prefix) {
		return acme.MalformedProblem(fmt.Sprintf("Key ID (account) in inner JWS body missing expected URL prefix (provided account value: %q)", innerContent.Account))
	}
	accountID := strings.TrimPrefix(innerContent.Account, prefix)
	if accountID == "" {
		return acme.MalformedProblem(fmt.Sprintf("No key ID (account) in inner JWS body (provided account value: %q)", innerContent.Account))
	}
	if accountID != existingAcct.ID {
		return acme.MalformedProblem(fmt.Sprintf("Key roll-over inner JWS body contains wrong account ID (provided account value: %q)", innerContent.Account))
	}

	// Verify inner key
	if !keyDigestEquals(innerContent.OldKey, *existingAcct.Key) {
		return acme.MalformedProblem("Key roll-over inner JWS body JSON contains wrong old key")
	}

	// Check for same key
	if keyDigestEquals(innerContent.OldKey, newKey) {
		return acme.MalformedProblem("New and old key are identical")
	}

	return nil
}

func (wfe *WebFrontEndImpl) KeyRollover(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request) {
	// Extract and parse outer JWS, and retrieve account
	outerPostData, prob := wfe.verifyPOST(request, wfe.lookupJWK)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	existingAcct, prob := wfe.getAcctByKey(outerPostData.jwk)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// Extract inner JWS
	parsedInnerJWS, err := wfe.parseJWS(string(outerPostData.body))
	if err != nil {
		wfe.sendError(acme.MalformedProblem(err.Error()), response)
		return
	}

	newPubKey, prob := wfe.extractJWK(request, parsedInnerJWS)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	innerPayload, prob := wfe.verifyJWSSignatureAndAlgorithm(newPubKey, parsedInnerJWS)
	if err != nil {
		prob.Detail = "inner JWS error: " + prob.Detail
		wfe.sendError(prob, response)
		return
	}

	innerHeaderURL, ok := wfe.extractJWSURL(parsedInnerJWS)
	if !ok {
		wfe.sendError(acme.MalformedProblem("Inner JWS header parameter 'url' required."), response)
		return
	}

	if innerHeaderURL != outerPostData.url {
		wfe.sendError(acme.MalformedProblem("JWS header parameter 'url' differs for inner and outer JWS."), response)
		return
	}

	prob = wfe.verifyKeyRollover(innerPayload, existingAcct, newPubKey, request)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// Ok, now change account key
	err = wfe.db.ChangeAccountKey(existingAcct, newPubKey)
	if err != nil {
		if existingAccountError, ok := err.(*db.ExistingAccountError); ok {
			acctURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", acctPath, existingAccountError.MatchingAccount.ID))
			response.Header().Set("Location", acctURL)
			response.WriteHeader(http.StatusConflict)
		} else {
			wfe.sendError(acme.InternalErrorProblem(fmt.Sprintf("Error rolling over account key (%s)", err.Error())), response)
		}
		return
	}

	response.WriteHeader(http.StatusOK)
}

func (wfe *WebFrontEndImpl) NewAccount(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request) {

	// We use extractJWK rather than lookupJWK here because the account is not yet
	// created, so the user provides the full key in a JWS header rather than
	// referring to an existing key.
	postData, prob := wfe.verifyPOST(request, wfe.extractJWK)
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
	err := json.Unmarshal(postData.body, &newAcctReq)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem("Error unmarshaling body JSON"), response)
		return
	}

	// Lookup existing account to exit early if it exists
	existingAcct, _ := wfe.db.GetAccountByKey(postData.jwk)
	if existingAcct != nil {
		if existingAcct.Status == acme.StatusDeactivated {
			// If there is an existing, but deactivated account, then return an unauthorized
			// problem informing the user that this account was deactivated
			wfe.sendError(acme.UnauthorizedProblem(
				"An account with the provided public key exists but is deactivated"), response)
		} else {
			// If there is an existing account then return a Location header pointing to
			// the account and a 200 OK response
			acctURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", acctPath, existingAcct.ID))
			response.Header().Set("Location", acctURL)
			_ = wfe.writeJSONResponse(response, http.StatusOK, existingAcct)
		}
		return
	} else if existingAcct == nil && newAcctReq.OnlyReturnExisting {
		// If there *isn't* an existing account and the created account request
		// contained OnlyReturnExisting then this is an error - return now before
		// creating a new account with the key
		wfe.sendError(acme.AccountDoesNotExistProblem(
			"unable to find existing account for only-return-existing request"), response)
		return
	}

	if !newAcctReq.ToSAgreed {
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
		Key: postData.jwk,
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
	err = wfe.writeJSONResponse(response, http.StatusCreated, newAcct)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling account"), response)
		return
	}
}

// isDNSCharacter is ported from Boulder's `policy/pa.go` implementation.
func isDNSCharacter(ch byte) bool {
	return ('a' <= ch && ch <= 'z') ||
		('A' <= ch && ch <= 'Z') ||
		('0' <= ch && ch <= '9') ||
		ch == '.' || ch == '-' || ch == '*'
}

/* TODO(@cpu): Pebble's validation of domain names is still pretty weak
 * compared to Boulder. We should consider adding:
 * 1) Checks for the # of labels, and the size of each label
 * 2) Checks against the Public Suffix List
 * 3) Checks against a configured domain blocklist
 * 4) Checks for malformed IDN, RLDH, etc
 */
// verifyOrder checks that a new order is considered well formed. Light
// validation is done on the order identifiers.
func (wfe *WebFrontEndImpl) verifyOrder(order *core.Order) *acme.ProblemDetails {
	// Lock the order for reading
	order.RLock()
	defer order.RUnlock()

	// Shouldn't happen - defensive check
	if order == nil {
		return acme.InternalErrorProblem("Order is nil")
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

		rawDomain := ident.Value
		if rawDomain == "" {
			return acme.MalformedProblem(fmt.Sprintf(
				"Order included DNS identifier with empty value"))
		}

		for _, ch := range []byte(rawDomain) {
			if !isDNSCharacter(ch) {
				return acme.MalformedProblem(fmt.Sprintf(
					"Order included DNS identifier with a value containing an illegal character: %q",
					ch))
			}
		}

		if len(rawDomain) > maxDNSIdentifierLength {
			return acme.MalformedProblem(fmt.Sprintf(
				"Order included DNS identifier that was longer than %d characters",
				maxDNSIdentifierLength))
		}

		if ip := net.ParseIP(rawDomain); ip != nil {
			return acme.MalformedProblem(fmt.Sprintf(
				"Order included a DNS identifier with an IP address value: %q\n",
				rawDomain))
		}

		if strings.HasSuffix(rawDomain, ".") {
			return acme.MalformedProblem(fmt.Sprintf(
				"Order included a DNS identifier with a value ending in a period: %q\n",
				rawDomain))
		}

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
		now := time.Now().UTC()
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
		enabledChallenges := []string{acme.ChallengeHTTP01, acme.ChallengeTLSALPN01, acme.ChallengeDNS01}
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
	authz.Challenges = chals
	authz.Unlock()
	return nil
}

// NewOrder creates a new Order request and populates its authorizations
func (wfe *WebFrontEndImpl) NewOrder(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request) {

	postData, prob := wfe.verifyPOST(request, wfe.lookupJWK)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	existingReg, prob := wfe.getAcctByKey(postData.jwk)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// Unpack the order request body
	var newOrder acme.Order
	err := json.Unmarshal(postData.body, &newOrder)
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
	if err := wfe.verifyOrder(order); err != nil {
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

	// Get the stored order back from the DB. The memorystore will set the order's
	// status for us.
	storedOrder := wfe.db.GetOrderByID(order.ID)

	orderURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", orderPath, storedOrder.ID))
	response.Header().Add("Location", orderURL)

	orderResp := wfe.orderForDisplay(storedOrder, request)
	err = wfe.writeJSONResponse(response, http.StatusCreated, orderResp)
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

	// Copy the initial OrderRequest from the internal order object to mutate and
	// use as the result.
	result := order.Order

	// Randomize the order of the order authorization URLs as well as the order's
	// identifiers. ACME draft Section 7.4 "Applying for Certificate Issuance"
	// says:
	//   Clients SHOULD NOT make any assumptions about the sort order of
	//   "identifiers" or "authorizations" elements in the returned order
	//   object.
	rand.Shuffle(len(result.Authorizations), func(i, j int) {
		result.Authorizations[i], result.Authorizations[j] = result.Authorizations[j], result.Authorizations[i]
	})
	rand.Shuffle(len(result.Identifiers), func(i, j int) {
		result.Identifiers[i], result.Identifiers[j] = result.Identifiers[j], result.Identifiers[i]
	})

	// Populate a finalization URL for this order
	result.Finalize = wfe.relativeEndpoint(request,
		fmt.Sprintf("%s%s", orderFinalizePath, order.ID))

	// If the order has a cert ID then set the certificate URL by constructing
	// a relative path based on the HTTP request & the cert ID
	if order.CertificateObject != nil {
		result.Certificate = wfe.relativeEndpoint(
			request,
			certPath+order.CertificateObject.ID)
	}

	return result
}

// Order retrieves the details of an existing order
func (wfe *WebFrontEndImpl) Order(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request) {
	postData, prob := wfe.verifyPOST(request, wfe.lookupJWK)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}
	account, prob := wfe.validPOSTAsGET(postData)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	orderID := strings.TrimPrefix(request.URL.Path, orderPath)
	order := wfe.db.GetOrderByID(orderID)
	if order == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	order.RLock()
	orderAccountID := order.AccountID
	defer order.RUnlock()

	// If the request was authenticated we need to make sure that the
	// authenticated account owns the order being requested
	if account != nil {
		if orderAccountID != account.ID {
			response.WriteHeader(http.StatusForbidden)
			wfe.sendError(acme.UnauthorizedProblem(
				"Account that authenticated the request does not own the specified order"), response)
			return
		}
	}

	// Prepare the order for display as JSON
	orderReq := wfe.orderForDisplay(order, request)
	err := wfe.writeJSONResponse(response, http.StatusOK, orderReq)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling order"), response)
		return
	}
}

func (wfe *WebFrontEndImpl) FinalizeOrder(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request) {

	// Verify the POST request
	postData, prob := wfe.verifyPOST(request, wfe.lookupJWK)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// Find the account corresponding to the key that authenticated the POST request
	existingAcct, prob := wfe.getAcctByKey(postData.jwk)
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

	if orderAccountID != existingAcct.ID {
		response.WriteHeader(http.StatusForbidden)
		wfe.sendError(acme.UnauthorizedProblem(
			"Account that authenticated the request does not own the specified order"), response)
		return
	}

	// The existing order must be in a ready status to finalize it
	if orderStatus != acme.StatusReady {
		wfe.sendError(acme.OrderNotReadyProblem(fmt.Sprintf(
			"Order's status (%q) was not %s", orderStatus, acme.StatusReady)), response)
		return
	}

	// The existing order must not be expired
	if orderExpires.Before(time.Now()) {
		wfe.sendError(acme.NotFoundProblem(fmt.Sprintf(
			"Order %q expired %s", orderID, orderExpires)), response)
		return
	}

	// The finalize POST body is expected to be the bytes from a base64 raw url
	// encoded CSR
	var finalizeMessage struct {
		CSR string
	}
	err := json.Unmarshal(postData.body, &finalizeMessage)
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
			"Order includes different number of names than CSR specifies"), response)
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

	// Lock and update the order with the parsed CSR and the began processing
	// state.
	existingOrder.Lock()
	existingOrder.ParsedCSR = parsedCSR
	existingOrder.BeganProcessing = true
	existingOrder.Unlock()

	// Ask the CA to complete the order in a separate goroutine.
	wfe.log.Printf("Order %s is fully authorized. Processing finalization", orderID)
	go wfe.ca.CompleteOrder(existingOrder)

	// Set the existingOrder to processing before displaying to the user
	existingOrder.Status = acme.StatusProcessing

	// Prepare the order for display as JSON
	orderReq := wfe.orderForDisplay(existingOrder, request)
	orderURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", orderPath, existingOrder.ID))
	response.Header().Add("Location", orderURL)
	err = wfe.writeJSONResponse(response, http.StatusOK, orderReq)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling order"), response)
		return
	}
}

// prepAuthorizationForDisplay prepares the provided acme.Authorization for
// display to an ACME client. It assumes the `authz` is already locked for
// reading by the caller.
func prepAuthorizationForDisplay(authz *core.Authorization) acme.Authorization {
	// Copy the authz to mutate and return
	result := authz.Authorization
	identVal := result.Identifier.Value

	// If the authorization identifier has a wildcard in the value, remove it and
	// set the Wildcard field to true
	if strings.HasPrefix(identVal, "*.") {
		result.Identifier.Value = strings.TrimPrefix(identVal, "*.")
		result.Wildcard = true
	}

	// Build a list of plain acme.Challenges to display using the core.Challenge
	// objects from the authorization.
	var chals []acme.Challenge
	for _, c := range authz.Challenges {
		c.RLock()
		// If the authz isn't pending then we need to filter the challenges displayed
		// to only those that were used to make the authz valid || invalid.
		if result.Status != acme.StatusPending && (c.Error == nil && c.Status != acme.StatusValid) {
			continue
		}
		chals = append(chals, c.Challenge)
		c.RUnlock()
	}
	result.Challenges = chals

	// Randomize the order of the challenges in the returned authorization.
	// Clients should not make any assumptions about the sort order.
	rand.Shuffle(len(result.Challenges), func(i, j int) {
		result.Challenges[i], result.Challenges[j] = result.Challenges[j], result.Challenges[i]
	})

	return result
}

func (wfe *WebFrontEndImpl) Authz(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request) {
	// There are two types of requests we might get:
	//   A) a POST to update the authorization
	//   B) a POST-as-GET to get the authorization
	postData, prob := wfe.verifyPOST(request, wfe.lookupJWK)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	authzID := strings.TrimPrefix(request.URL.Path, authzPath)
	authz := wfe.db.GetAuthorizationByID(authzID)
	if authz == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}

	authz.Lock()
	defer authz.Unlock()
	authz.Order.RLock()
	orderAcctID := authz.Order.AccountID
	authz.Order.RUnlock()

	// If the postData is not a POST-as-GET, treat this as case A) and update
	// the authorization based on the postData
	if !postData.postAsGet {
		existingAcct, prob := wfe.getAcctByKey(postData.jwk)
		if prob != nil {
			wfe.sendError(prob, response)
			return
		}

		if orderAcctID != existingAcct.ID {
			wfe.sendError(acme.UnauthorizedProblem(
				"Account does not own authorization"), response)
			return
		}

		var deactivateRequest struct {
			Status string
		}
		err := json.Unmarshal(postData.body, &deactivateRequest)
		if err != nil {
			wfe.sendError(acme.MalformedProblem(
				fmt.Sprintf("Malformed authorization update: %s",
					err.Error())), response)
			return
		}

		if deactivateRequest.Status != "deactivated" {
			wfe.sendError(acme.MalformedProblem(
				fmt.Sprintf("Malformed authorization update, status must be \"deactivated\" not %q",
					deactivateRequest.Status)), response)
			return
		}
		authz.Status = acme.StatusDeactivated
	} else {
		// Otherwise this was a POST-as-GET request and we need to verify it
		// accordingly and ensure the authorized account owns the authorization
		// being fetched.
		account, prob := wfe.validPOSTAsGET(postData)
		if prob != nil {
			wfe.sendError(prob, response)
			return
		}

		if orderAcctID != account.ID {
			response.WriteHeader(http.StatusForbidden)
			wfe.sendError(acme.UnauthorizedProblem(
				"Account authorizing the request is not the owner of the authorization"),
				response)
			return
		}
	}

	err := wfe.writeJSONResponse(
		response,
		http.StatusOK,
		prepAuthorizationForDisplay(authz))
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling authz"), response)
		return
	}
}

func (wfe *WebFrontEndImpl) Challenge(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request) {
	// There are two possibilities:
	// A) request is a POST to begin a challenge
	// B) request is a POST-as-GET to poll a challenge
	postData, prob := wfe.verifyPOST(request, wfe.lookupJWK)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	chalID := strings.TrimPrefix(request.URL.Path, challengePath)
	chal := wfe.db.GetChallengeByID(chalID)
	if chal == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}

	// If the post isn't a POST-as-GET its case A)
	var account *core.Account
	if !postData.postAsGet {
		wfe.updateChallenge(postData, response, request)
		return
	} else {
		// Otherwise it is case B)
		account, prob = wfe.validPOSTAsGET(postData)
		if prob != nil {
			wfe.sendError(prob, response)
			return
		}
	}

	// Lock the challenge for reading in order to write the response
	chal.RLock()
	defer chal.RUnlock()

	if chal.Authz.Order.AccountID != account.ID {
		response.WriteHeader(http.StatusUnauthorized)
		wfe.sendError(acme.UnauthorizedProblem(
			"Account authenticating request is not the owner of the challenge"), response)
		return
	}

	err := wfe.writeJSONResponse(response, http.StatusOK, chal.Challenge)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling challenge"), response)
		return
	}
}

// getAcctByKey finds a account by key or returns a problem pointer if an
// existing account can't be found or the key is invalid.
func (wfe *WebFrontEndImpl) getAcctByKey(key crypto.PublicKey) (*core.Account, *acme.ProblemDetails) {
	// Find the existing account object for that key
	existingAcct, err := wfe.db.GetAccountByKey(key)
	if err != nil {
		return nil, acme.AccountDoesNotExistProblem("Error while retrieving key ID from public key")
	}
	if existingAcct == nil {
		return nil, acme.AccountDoesNotExistProblem(
			"URL in JWS 'kid' field does not correspond to an account")
	}

	if existingAcct.Status == acme.StatusDeactivated {
		return nil, acme.UnauthorizedProblem("Account has been deactivated")
	}
	return existingAcct, nil
}

func (wfe *WebFrontEndImpl) validateChallengeUpdate(
	chal *core.Challenge) (*core.Authorization, *acme.ProblemDetails) {
	// Lock the challenge for reading to do validation
	chal.RLock()
	defer chal.RUnlock()

	// Check that the existing challenge is Pending
	if chal.Status != acme.StatusPending {
		return nil, acme.MalformedProblem(
			fmt.Sprintf("Cannot update challenge with status %s, only status %s",
				chal.Status, acme.StatusPending))
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

	now := time.Now()
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
	postData *authenticatedPOST,
	response http.ResponseWriter,
	request *http.Request) {

	existingAcct, prob := wfe.getAcctByKey(postData.jwk)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	var chalResp struct {
		KeyAuthorization *string
	}
	err := json.Unmarshal(postData.body, &chalResp)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem("Error unmarshaling body JSON"), response)
		return
	}

	// Historically challenges were updated by POSTing a KeyAuthorization. This is
	// unnecessary, the server can calculate this itself. We could ignore this if
	// sent (and that's what Boulder will do) but for Pebble we'd like to offer
	// a way to be more aggressive about pushing clients implementations in the
	// right direction, so we treat this as a malformed request.
	if chalResp.KeyAuthorization != nil {
		wfe.sendError(
			acme.MalformedProblem(
				"Challenge response body contained legacy KeyAuthorization field, "+
					"POST body should be `{}`"), response)
		return
	}

	chalID := strings.TrimPrefix(request.URL.Path, challengePath)
	existingChal := wfe.db.GetChallengeByID(chalID)
	if existingChal == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}

	authz, prob := wfe.validateChallengeUpdate(existingChal)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}
	if authz == nil {
		wfe.sendError(
			acme.InternalErrorProblem("challenge missing associated authz"), response)
		return
	}

	authz.RLock()
	authz.Order.RLock()
	orderAcctID := authz.Order.AccountID
	authz.Order.RUnlock()
	authz.RUnlock()

	if orderAcctID != existingAcct.ID {
		response.WriteHeader(http.StatusUnauthorized)
		wfe.sendError(acme.UnauthorizedProblem(
			"Account authenticating request is not the owner of the challenge"), response)
		return
	}

	existingOrder, prob := wfe.validateAuthzForChallenge(authz)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// Lock the order for reading to check the expiry date
	existingOrder.RLock()
	now := time.Now()
	if now.After(existingOrder.ExpiresDate) {
		wfe.sendError(
			acme.MalformedProblem(fmt.Sprintf("order expired %s",
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
	err = wfe.writeJSONResponse(response, http.StatusOK, existingChal.Challenge)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling challenge"), response)
		return
	}
}

func (wfe *WebFrontEndImpl) Certificate(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request) {
	postData, prob := wfe.verifyPOST(request, wfe.lookupJWK)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}
	acct, prob := wfe.validPOSTAsGET(postData)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	serial := strings.TrimPrefix(request.URL.Path, certPath)
	cert := wfe.db.GetCertificateByID(serial)
	if cert == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}

	if cert.AccountID != acct.ID {
		response.WriteHeader(http.StatusUnauthorized)
		wfe.sendError(acme.UnauthorizedProblem(
			"Account authenticating request does not own certificate"), response)
		return
	}

	response.Header().Set("Content-Type", "application/pem-certificate-chain; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(cert.Chain())
}

func (wfe *WebFrontEndImpl) writeJSONResponse(response http.ResponseWriter, status int, v interface{}) error {
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

// RevokeCert revokes an ACME certificate.
// It currently only implements one method of ACME revocation:
// Signing the revocation request by signing it with the certificate
// to be revoked's private key and embedding the certificate
// to be revoked's public key as a JWK in the JWS.
//
// Pebble's idea of certificate revocation is to forget the certificate exists.
// This method does not percolate to a CRL or an OCSP response.
func (wfe *WebFrontEndImpl) RevokeCert(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request) {

	// The ACME specification handles the verification of revocation requests
	// differently from other endpoints that always use one JWS authentication
	// method. For this endpoint we need to accept a JWS with an embedded JWK, or
	// a JWS with an embedded key ID, handling each case differently in terms of
	// which certificates are authorized to be revoked by the requester

	bodyBytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		wfe.sendError(
			acme.InternalErrorProblem("unable to read request body"), response)
		return
	}
	body := string(bodyBytes)

	parsedJWS, err := wfe.parseJWS(body)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem(err.Error()), response)
		return
	}

	if prob := wfe.validPOST(request); prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// Determine the authentication type for this request
	authType, prob := checkJWSAuthType(parsedJWS)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	// Handle the revocation request according to how it is authenticated, or if
	// the authentication type is unknown, error immediately
	if authType == embeddedKeyID {
		prob = wfe.revokeCertByKeyID(parsedJWS, request)
	} else if authType == embeddedJWK {
		prob = wfe.revokeCertByJWK(parsedJWS, request)
	} else {
		prob = acme.MalformedProblem("Malformed JWS, no KeyID or embedded JWK")
	}
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	response.WriteHeader(http.StatusOK)
}

func (wfe *WebFrontEndImpl) revokeCertByKeyID(
	jws *jose.JSONWebSignature,
	request *http.Request) *acme.ProblemDetails {

	pubKey, prob := wfe.lookupJWK(request, jws)
	if prob != nil {
		return prob
	}

	postData, prob := wfe.verifyJWS(pubKey, jws, request)
	if prob != nil {
		return prob
	}

	existingAcct, err := wfe.db.GetAccountByKey(postData.jwk)
	if err != nil {
		return acme.MalformedProblem(fmt.Sprintf("Cannot obtain key ID from public key (%s)", err.Error()))
	}
	if existingAcct == nil {
		return acme.UnauthorizedProblem("No account found corresponding to public key authenticating this request")
	}

	// An account is only authorized to revoke its own certificates presently.
	// TODO(@cpu): Allow an account to revoke another account's certificate if
	// the revoker account has valid authorizations for all of the names in the
	// to-be-revoked certificate.
	authorizedToRevoke := func(cert *core.Certificate) *acme.ProblemDetails {
		if cert.AccountID == existingAcct.ID {
			return nil
		}
		return acme.UnauthorizedProblem(
			fmt.Sprintf(
				"The certificate being revoked is not associated with account %q",
				existingAcct.ID))
	}
	return wfe.processRevocation(postData.body, authorizedToRevoke)
}

func (wfe *WebFrontEndImpl) revokeCertByJWK(
	jws *jose.JSONWebSignature,
	request *http.Request) *acme.ProblemDetails {

	var requestKey *jose.JSONWebKey
	pubKey, prob := wfe.extractJWK(request, jws)
	if prob != nil {
		return prob
	}
	postData, prob := wfe.verifyJWS(pubKey, jws, request)
	if prob != nil {
		return prob
	}
	requestKey = postData.jwk

	// For embedded JWK revocations we decide if a requester is able to revoke a specific
	// certificate by checking that to-be-revoked certificate has the same public
	// key as the JWK that was used to authenticate the request
	authorizedToRevoke := func(cert *core.Certificate) *acme.ProblemDetails {
		if keyDigestEquals(requestKey, cert.Cert.PublicKey) {
			return nil
		}
		return acme.UnauthorizedProblem(
			"JWK embedded in revocation request must be the same public key as the cert to be revoked")
	}
	return wfe.processRevocation(postData.body, authorizedToRevoke)
}

// authorizedToRevokeCert is a callback function that can be used to validate if
// a given requester is authorized to revoke the certificate parsed out of the
// revocation request. If the requester is not authorized to revoke the
// certificate a problem is returned. It is expected to be a closure containing
// additional state (an account ID or key) that will be used to make the
// decision.
type authorizedToRevokeCert func(*core.Certificate) *acme.ProblemDetails

func (wfe *WebFrontEndImpl) processRevocation(
	jwsBody []byte,
	authorizedToRevoke authorizedToRevokeCert) *acme.ProblemDetails {

	// revokeCertReq is the ACME certificate information submitted by the client
	var revokeCertReq struct {
		Certificate string `json:"certificate"`
		Reason      *uint  `json:"reason,omitempty"`
	}
	err := json.Unmarshal(jwsBody, &revokeCertReq)
	if err != nil {
		return acme.MalformedProblem("Error unmarshaling certificate revocation JSON body")
	}

	if revokeCertReq.Reason != nil {
		r := *revokeCertReq.Reason
		if r == unusedRevocationReason || r > aACompromiseRevocationReason {
			return acme.BadRevocationReasonProblem(fmt.Sprintf("Invalid revocation reason: %d", r))
		}
	}

	derBytes, err := base64.RawURLEncoding.DecodeString(revokeCertReq.Certificate)
	if err != nil {
		return acme.MalformedProblem("Error decoding Base64url-encoded DER: " + err.Error())
	}

	cert := wfe.db.GetCertificateByDER(derBytes)
	if cert == nil {
		cert := wfe.db.GetRevokedCertificateByDER(derBytes)
		if cert != nil {
			return acme.AlreadyRevokedProblem(
				"Certificate has already been revoked.")
		} else {
			return acme.MalformedProblem(
				"Unable to find specified certificate.")
		}
	}

	if prob := authorizedToRevoke(cert); prob != nil {
		return prob
	}

	wfe.db.RevokeCertificate(cert)
	return nil
}
