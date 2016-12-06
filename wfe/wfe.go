package wfe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/letsencrypt/pebble/acme"
	jose "github.com/square/go-jose"
)

const (
	// Note: We deliberately pick endpoint paths that differ from Boulder to
	// exercise clients processing of the /directory response
	directoryPath = "/dir"
	noncePath     = "/nonce-plz"
)

// TODO(@cpu) - externalize Problem code to another package
type ProblemDetails struct {
	Type       string `json:"type,omitempty"`
	Detail     string `json:"detail,omitempty"`
	HTTPStatus int    `json:"status,omitempty"`
}

func (pd *ProblemDetails) Error() string {
	return fmt.Sprintf("%s :: %s", pd.Type, pd.Detail)
}

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
	SubscriberAgreementURL string
	nonce                  *nonceMap
}

func New() (WebFrontEndImpl, error) {
	return WebFrontEndImpl{
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
	// Note: "GET" also implies "HEAD"
	wfe.HandleFunc(m, noncePath, wfe.Nonce, "GET")
	return m
}

func (wfe *WebFrontEndImpl) Directory(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	directoryEndpoints := map[string]string{
		"new-nonce": noncePath,
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
	response.Write([]byte("{}"))
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

func (wfe *WebFrontEndImpl) verifyPOST(
	ctx context.Context,
	logEvent *requestEvent,
	request *http.Request,
	resource acme.Resource) *acme.ProblemDetails {

	if _, ok := request.Header["Content-Length"]; !ok {
		return acme.MalformedProblem("missing Content-Length header on POST")
	}

	if request.Body == nil {
		return acme.MalformedProblem("no body on POST")
	}

	bodyBytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return acme.InternalErrorProblem("unable to read request body")
	}

	body := string(bodyBytes)

	submittedKey, parsedJWS, err := wfe.extractJWSKey(body)
	if err != nil {
		return acme.MalformedProblem(err.Error())
	}

	// TODO(@cpu): Find a reg with this key

	// TODO(@cpu): `checkAlgorithm()`

	// TODO(@cpu): use the looked up key, not submittedKey!
	payload, err := parsedJWS.Verify(submittedKey)
	if err != nil {
		return acme.MalformedProblem("JWS verification error")
	}

	nonce := parsedJWS.Signatures[0].Header.Nonce
	if len(nonce) == 0 {
		return acme.BadNonceProblem("JWS has no anti-replay nonce")
	} else if !wfe.nonce.validNonce(nonce) {
		return acme.BadNonceProblem(fmt.Sprintf(
			"JWS has an invalid anti-replay nonce: %s", nonce))
	}

	var parsedRequest struct {
		Resource string `json:"resource"`
	}
	err = json.Unmarshal([]byte(payload), &parsedRequest)
	if err != nil {
		return acme.MalformedProblem("Request payload did not parse as JSON")
	}
	if parsedRequest.Resource == "" {
		return acme.MalformedProblem(
			"JWS request payload does not specify a resource")
	} else if resource != acme.Resource(parsedRequest.Resource) {
		return acme.MalformedProblem(
			"JWS request payload resource does not match known resource")
	}

	return nil
}

func addNoCacheHeader(response http.ResponseWriter) {
	response.Header().Add("Cache-Control", "public, max-age=0, no-cache")
}

func marshalIndent(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "   ")
}
