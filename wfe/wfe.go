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
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/pebble/acme"
	"github.com/letsencrypt/pebble/core"
	"github.com/letsencrypt/pebble/db"
	"github.com/letsencrypt/pebble/va"
)

const (
	// Note: We deliberately pick endpoint paths that differ from Boulder to
	// exercise clients processing of the /directory response
	directoryPath  = "/dir"
	noncePath      = "/nonce-plz"
	newAccountPath = "/sign-me-up"
	acctPath       = "/my-account/"
	newOrderPath   = "/order-plz"
	orderPath      = "/my-order/"
	authzPath      = "/authZ/"
	challengePath  = "/chalZ/"
	certPath       = "/certZ/"

	// How long do pending authorizations last before expiring?
	pendingAuthzExpire = time.Hour
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
	log   *log.Logger
	db    *db.MemoryStore
	nonce *nonceMap
	clk   clock.Clock
	va    *va.VAImpl
}

const ToSURL = "data:text/plain,Do%20what%20thou%20wilt"

func New(
	log *log.Logger,
	clk clock.Clock,
	db *db.MemoryStore,
	va *va.VAImpl) WebFrontEndImpl {
	return WebFrontEndImpl{
		log:   log,
		db:    db,
		nonce: newNonceMap(),
		clk:   clk,
		va:    va,
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

	response.Header().Set("Content-Type", "application/problem+json")
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
		"new-nonce":   noncePath,
		"new-account": newAccountPath,
		"new-order":   newOrderPath,
	}

	response.Header().Set("Content-Type", "application/json")

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
		"terms-of-service": ToSURL,
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
func (wfe *WebFrontEndImpl) extractJWK(_ *http.Request, jws *jose.JSONWebSignature) (*jose.JSONWebKey, error) {
	header := jws.Signatures[0].Header
	if header.KeyID != "" {
		return nil, errors.New("jwk and kid header fields are mutually exclusive.")
	}
	key := header.JSONWebKey
	if key == nil {
		return nil, errors.New("No JWK in JWS header")
	}

	if !key.Valid() {
		return nil, errors.New("Invalid JWK in JWS header")
	}

	return key, nil
}

// lookupJWK returns a JSONWebKey referenced by the "kid" (key id) field in a JWS header.
func (wfe *WebFrontEndImpl) lookupJWK(request *http.Request, jws *jose.JSONWebSignature) (*jose.JSONWebKey, error) {
	header := jws.Signatures[0].Header
	if header.JSONWebKey != nil {
		return nil, errors.New("jwk and kid header fields are mutually exclusive.")
	}
	accountURL := header.KeyID
	prefix := wfe.relativeEndpoint(request, acctPath)
	accountID := strings.TrimPrefix(accountURL, prefix)
	account := wfe.db.GetAccountByID(accountID)
	if account == nil {
		return nil, fmt.Errorf("Account %s not found.", accountURL)
	}
	return account.Key, nil
}

// keyExtractor is a function that returns a JSONWebKey based on input from a
// user-provided JSONWebSignature, for instance by extracting it from the input,
// or by looking it up in a database based on the input.
type keyExtractor func(*http.Request, *jose.JSONWebSignature) (*jose.JSONWebKey, error)

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

	pubKey, err := kx(request, parsedJWS)
	if err != nil {
		return nil, nil, acme.MalformedProblem(err.Error())
	}

	// TODO(@cpu): `checkAlgorithm()`

	payload, err := parsedJWS.Verify(pubKey)
	if err != nil {
		return nil, nil, acme.MalformedProblem("JWS verification error")
	}

	nonce := parsedJWS.Signatures[0].Header.Nonce
	if len(nonce) == 0 {
		return nil, nil, acme.BadNonceProblem("JWS has no anti-replay nonce")
	} else if !wfe.nonce.validNonce(nonce) {
		return nil, nil, acme.BadNonceProblem(fmt.Sprintf(
			"JWS has an invalid anti-replay nonce: %s", nonce))
	}

	headerURL, ok := parsedJWS.Signatures[0].Header.ExtraHeaders[jose.HeaderKey("url")].(string)
	if !ok || len(headerURL) == 0 {
		return nil, nil, acme.MalformedProblem("JWS header parameter 'url' required.")
	}
	expectedURL := url.URL{
		Scheme: "http",
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

	// newAcct is the ACME account information submitted by the client
	var newAcct acme.Account
	err := json.Unmarshal(body, &newAcct)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem("Error unmarshaling body JSON"), response)
		return
	}

	// createdAcct is the internal Pebble account object
	createdAcct := core.Account{
		Account: newAcct,
		Key:     key,
	}
	keyID, err := keyToID(key)
	if err != nil {
		wfe.sendError(acme.MalformedProblem(err.Error()), response)
		return
	}
	createdAcct.ID = keyID

	// NOTE: We don't use wfe.getAccountByKey here because we want to treat a
	//       "missing" account as a non-error
	if existingAcct := wfe.db.GetAccountByID(createdAcct.ID); existingAcct != nil {
		acctURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", acctPath, existingAcct.ID))
		response.Header().Set("Location", acctURL)
		wfe.sendError(acme.Conflict("Account key is already in use"), response)
		return
	}

	if newAcct.ToSAgreed == false {
		response.Header().Add("Link", link(ToSURL, "terms-of-service"))
		wfe.sendError(
			acme.AgreementRequiredProblem(
				"Provided account did not agree to the terms of service"),
			response)
		return
	}

	count, err := wfe.db.AddAccount(&createdAcct)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error saving account"), response)
		return
	}
	wfe.log.Printf("There are now %d accounts in memory\n", count)

	acctURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", acctPath, createdAcct.ID))

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
	csr := order.ParsedCSR
	if csr == nil {
		return acme.InternalErrorProblem("Parsed CSR is nil")
	}
	if len(csr.DNSNames) == 0 {
		return acme.MalformedProblem("CSR has no names in it")
	}
	orderKeyID, err := keyToID(csr.PublicKey)
	if err != nil {
		return acme.MalformedProblem("CSR has an invalid PublicKey")
	}
	if orderKeyID == reg.ID {
		return acme.MalformedProblem("Certificate public key must be different than account key")
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
	for _, name := range order.ParsedCSR.DNSNames {
		ident := acme.Identifier{
			Type:  acme.IdentifierDNS,
			Value: name,
		}
		now := wfe.clk.Now().UTC()
		expires := now.Add(pendingAuthzExpire)
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

	enabledChallenges := []string{acme.ChallengeHTTP01, acme.ChallengeTLSSNI02, acme.ChallengeDNS01}
	for _, chalType := range enabledChallenges {
		chal, err := wfe.makeChallenge(chalType, authz, request)
		if err != nil {
			return err
		}
		chals = append(chals, chal)
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

	// Decode and parse the CSR bytes from the order
	csrBytes, err := base64.RawURLEncoding.DecodeString(newOrder.CSR)
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
	expires := time.Now().AddDate(0, 0, 1)
	order := &core.Order{
		ID: newToken(),
		Order: acme.Order{
			Status:  acme.StatusPending,
			Expires: expires.UTC().Format(time.RFC3339),
			// Only the CSR, NotBefore and NotAfter fields of the client request are
			// copied as-is
			CSR:       newOrder.CSR,
			NotBefore: newOrder.NotBefore,
			NotAfter:  newOrder.NotAfter,
		},
		ExpiresDate: expires,
		ParsedCSR:   parsedCSR,
	}

	// Verify the details of the order before creating authorizations
	if err := wfe.verifyOrder(order, existingReg); err != nil {
		wfe.sendError(err, response)
		return
	}

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

	orderURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", orderPath, order.ID))
	response.Header().Add("Location", orderURL)
	err = wfe.writeJsonResponse(response, http.StatusCreated, order.Order)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling order"), response)
		return
	}
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

	// Lock the order for reading
	order.RLock()
	defer order.RUnlock()

	// If the order has a cert ID then set the certificate URL by constructing
	// a relative path based on the HTTP request & the cert ID
	if order.CertificateObject != nil {
		order.Certificate = wfe.relativeEndpoint(
			request,
			certPath+order.CertificateObject.ID)
	}

	// Return only the initial OrderRequest not the internal object with the
	// parsedCSR
	orderReq := order.Order

	err := wfe.writeJsonResponse(response, http.StatusOK, orderReq)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling order"), response)
		return
	}
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

	err := wfe.writeJsonResponse(response, http.StatusOK, authz.Authorization)
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
		return nil, acme.MalformedProblem("No existing account for signer's public key")
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

	// Check that the challenge update is the same type as the challenge
	// NOTE: Boulder doesn't do this at the time of writing and instead increments
	//       a "StartChallengeWrongType" stat
	if update.Type != chal.Type {
		return nil, acme.MalformedProblem(
			fmt.Sprintf("Challenge update was type %s, existing challenge is type %s",
				update.Type, chal.Type))
	}

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
			fmt.Sprintf("Authorization expired %s %s",
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

	response.Header().Set("Content-Type", "application/pem-certificate-chain")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(cert.Chain())
}

func (wfe *WebFrontEndImpl) writeJsonResponse(response http.ResponseWriter, status int, v interface{}) error {
	jsonReply, err := marshalIndent(v)
	if err != nil {
		return err // All callers are responsible for handling this error
	}

	response.Header().Set("Content-Type", "application/json")
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
