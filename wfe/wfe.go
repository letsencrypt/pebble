package wfe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const (
	// Note: We deliberately pick endpoint paths that differ from Boulder to
	// exercise clients processing of the /directory response
	directoryPath = "/dir"
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
}

func New() (WebFrontEndImpl, error) {
	return WebFrontEndImpl{}, nil
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
				// TODO(@cpu): generate nonces...
				response.Header().Set("Replay-Nonce", "TODO...")

				logEvent.Endpoint = pattern
				if request.URL != nil {
					logEvent.Endpoint = path.Join(logEvent.Endpoint, request.URL.Path)
				}

				addNoCacheHeader(response)

				if !methodsMap[request.Method] {
					response.Header().Set("Allow", methodsStr)
					wfe.sendError(response)
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

func (wfe *WebFrontEndImpl) sendError(response http.ResponseWriter) {
	// TODO(@cpu): Support problems & varied error codes
	code := http.StatusInternalServerError

	problemDoc, err := marshalIndent(&ProblemDetails{
		Type:       "urn:acme:error:serverInternal",
		Detail:     "An unknown internal server error occurred",
		HTTPStatus: http.StatusInternalServerError,
	})
	if err != nil {
		problemDoc = []byte("{\"detail\": \"Problem marshalling error message.\"}")
	}

	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(code)
	response.Write(problemDoc)
}

func (wfe *WebFrontEndImpl) Handler() http.Handler {
	m := http.NewServeMux()
	wfe.HandleFunc(m, directoryPath, wfe.Directory, "GET")
	return m
}

func (wfe *WebFrontEndImpl) Directory(
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	directoryEndpoints := map[string]string{}

	response.Header().Set("Content-Type", "application/json")

	relDir, err := wfe.relativeDirectory(request, directoryEndpoints)
	if err != nil {
		wfe.sendError(response)
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

func addNoCacheHeader(response http.ResponseWriter) {
	response.Header().Add("Cache-Control", "public, max-age=0, no-cache")
}

func marshalIndent(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "   ")
}
