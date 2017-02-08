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

	"github.com/letsencrypt/pebble/acme"
	"gopkg.in/square/go-jose.v1"
)

const (
	// Note: We deliberately pick endpoint paths that differ from Boulder to
	// exercise clients processing of the /directory response
	directoryPath = "/dir"
	noncePath     = "/nonce-plz"
	newRegPath    = "/sign-me-up"
	regPath       = "/my-reg/"
	newOrderPath  = "/order-plz"
	orderPath     = "/my-order/"
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
	log                    *log.Logger
	db                     *memoryStore
	nonce                  *nonceMap
	SubscriberAgreementURL string
}

func New(log *log.Logger) (WebFrontEndImpl, error) {
	return WebFrontEndImpl{
		log:   log,
		db:    newMemoryStore(),
		nonce: newNonceMap(),
	}, nil
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
	wfe.HandleFunc(m, newRegPath, wfe.NewRegistration, "POST")
	wfe.HandleFunc(m, newOrderPath, wfe.NewOrder, "POST")
	wfe.HandleFunc(m, orderPath, wfe.Order, "GET")

	// TODO(@cpu): Handle regPath for existing reg updates
	return m
}

func (wfe *WebFrontEndImpl) Directory(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	// TODO(@cpu): Add directory metadata (e.g. TOS url)
	directoryEndpoints := map[string]string{
		"new-nonce": noncePath,
		"new-reg":   newRegPath,
		"new-order": newOrderPath,
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
	relativeDir := make(map[string]string, len(directory))

	for k, v := range directory {
		relativeDir[k] = wfe.relativeEndpoint(request, v)
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
 * over a provided public key. We use this for acme.Registration ID values
 * because it makes looking up a registration by key easy (required by the spec
 * for retreiving existing registrations), and becauase it makes the reg URLs
 * somewhat human digestable/comparable.
 */
func keyToID(key crypto.PublicKey) (string, error) {
	switch t := key.(type) {
	case *jose.JsonWebKey:
		if t == nil {
			return "", fmt.Errorf("Cannot compute ID of nil key")
		}
		return keyToID(t.Key)
	case jose.JsonWebKey:
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

func (wfe *WebFrontEndImpl) extractJWSKey(body string) (*jose.JsonWebKey, *jose.JsonWebSignature, error) {
	parsedJWS, err := jose.ParseSigned(body)
	if err != nil {
		return nil, nil, errors.New("Parse error reading JWS")
	}

	if len(parsedJWS.Signatures) > 1 {
		return nil, nil, errors.New("Too many signatures in POST body")
	}

	if len(parsedJWS.Signatures) == 0 {
		return nil, nil, errors.New("POST JWS not signed")
	}

	key := parsedJWS.Signatures[0].Header.JsonWebKey
	if key == nil {
		return nil, nil, errors.New("No JWK in JWS header")
	}

	if !key.Valid() {
		return nil, nil, errors.New("Invalid JWK in JWS header")
	}

	return key, parsedJWS, nil
}

// NOTE: Unlike `verifyPOST` from the Boulder WFE this version does not
// presently handle the `regCheck` parameter or do any lookups for existing
// registrations.
func (wfe *WebFrontEndImpl) verifyPOST(
	ctx context.Context,
	logEvent *requestEvent,
	request *http.Request,
	resource acme.Resource) ([]byte, *jose.JsonWebKey, *acme.ProblemDetails) {

	if _, ok := request.Header["Content-Length"]; !ok {
		return nil, nil, acme.MalformedProblem("missing Content-Length header on POST")
	}

	if request.Body == nil {
		return nil, nil, acme.MalformedProblem("no body on POST")
	}

	bodyBytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return nil, nil, acme.InternalErrorProblem("unable to read request body")
	}

	body := string(bodyBytes)

	submittedKey, parsedJWS, err := wfe.extractJWSKey(body)
	if err != nil {
		return nil, nil, acme.MalformedProblem(err.Error())
	}

	// TODO(@cpu): `checkAlgorithm()`

	payload, err := parsedJWS.Verify(submittedKey)
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

	var parsedRequest struct {
		Resource string `json:"resource"`
	}
	err = json.Unmarshal([]byte(payload), &parsedRequest)
	if err != nil {
		return nil, nil, acme.MalformedProblem("Request payload did not parse as JSON")
	}

	if parsedRequest.Resource == "" {
		return nil, nil, acme.MalformedProblem(
			"JWS request payload does not specify a resource")
	} else if resource != acme.Resource(parsedRequest.Resource) {
		return nil, nil, acme.MalformedProblem(
			"JWS request payload resource does not match known resource")
	}

	return []byte(payload), submittedKey, nil
}

func (wfe *WebFrontEndImpl) NewRegistration(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	body, key, prob := wfe.verifyPOST(ctx, logEvent, request, acme.ResourceNewReg)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	var newReg acme.Registration
	err := json.Unmarshal(body, &newReg)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem("Error unmarshaling body JSON"), response)
		return
	}

	newReg.Key = key
	regID, err := keyToID(newReg.Key)
	if err != nil {
		wfe.sendError(acme.MalformedProblem(err.Error()), response)
		return
	}
	newReg.ID = regID

	if existingReg := wfe.db.getRegistrationByID(newReg.ID); existingReg != nil {
		regURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", regPath, existingReg.ID))
		response.Header().Set("Location", regURL)
		wfe.sendError(acme.Conflict("Registration key is already in use"), response)
		return
	}

	if newReg.ToSAgreed == false {
		response.Header().Add("Link", link(wfe.SubscriberAgreementURL, "terms-of-service"))
		wfe.sendError(
			acme.AgreementRequiredProblem(
				"Provided registration did include true terms-of-service-agreed"),
			response)
		return
	}

	wfe.db.addRegistration(&newReg)
	wfe.log.Printf("There are now %d registrations in memory\n", wfe.db.countRegistrations())

	regURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", regPath, newReg.ID))

	response.Header().Add("Location", regURL)
	err = wfe.writeJsonResponse(response, http.StatusCreated, newReg)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling registration"), response)
	}
}

func (wfe *WebFrontEndImpl) validateOrder(order *acme.Order) error {
	// TODO(@cpu) - Apply some more advanced policy decisions on the CSR
	return nil
}

func (wfe *WebFrontEndImpl) NewOrder(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	body, key, prob := wfe.verifyPOST(ctx, logEvent, request, acme.ResourceNewOrder)
	if prob != nil {
		wfe.sendError(prob, response)
		return
	}

	regID, err := keyToID(key)
	if err != nil {
		wfe.log.Printf("keyToID err: %s\n", err.Error())
		wfe.sendError(acme.MalformedProblem("Error computing key digest"), response)
		return
	}
	wfe.log.Printf("received new-order req from reg ID %s\n", regID)

	var existingReg *acme.Registration
	if existingReg = wfe.db.getRegistrationByID(regID); existingReg == nil {
		wfe.sendError(
			acme.MalformedProblem(
				fmt.Sprintf("No existing registration with ID %q", regID)),
			response)
		return
	}

	var newOrder acme.OrderRequest
	err = json.Unmarshal(body, &newOrder)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem("Error unmarshaling body JSON"), response)
		return
	}

	csrBytes, err := base64.URLEncoding.DecodeString(newOrder.CSR)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem("Error decoding Base64url-encoded CSR"), response)
		return
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		wfe.sendError(
			acme.MalformedProblem("Error parsing Base64url-encoded CSR"), response)
		return
	}

	order := &acme.Order{
		OrderRequest: newOrder,
		ParsedCSR:    parsedCSR,
	}
	order.ID = acme.NewToken()
	fmt.Printf("Order: %#v\n", order)

	if err := wfe.validateOrder(order); err != nil {
		wfe.sendError(
			// TODO(@cpu) validateOrder should return a problem (e.g.
			// rejectedIdentifier, unsupportedIdentifier, etc) as appropriate
			acme.MalformedProblem(
				fmt.Sprintf("Error validating order: %s", err.Error())), response)
		return
	}

	_, err = wfe.db.addOrder(order)
	if err != nil {
		wfe.sendError(
			acme.InternalErrorProblem("Error saving order"), response)
		return
	}

	orderURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", orderPath, order.ID))
	response.Header().Add("Location", orderURL)
	err = wfe.writeJsonResponse(response, http.StatusCreated, newOrder)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling order"), response)
		return
	}
}

func (wfe *WebFrontEndImpl) Order(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	orderID := strings.TrimPrefix(request.URL.Path, orderPath)
	fmt.Printf("Order ID: %#v\n", orderID)

	order := wfe.db.getOrderByID(orderID)
	if order == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}

	err := wfe.writeJsonResponse(response, http.StatusOK, order)
	if err != nil {
		wfe.sendError(acme.InternalErrorProblem("Error marshalling order"), response)
		return
	}
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
