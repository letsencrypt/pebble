package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/letsencrypt/challtestsrv"
)

// clearHistory handles an HTTP POST request to clear the challenge server
// request history for a specific type of event.
//
// The POST body is expected to have one parameter:
// "type" - the type of event to clear. May be "http", "dns", or "tlsalpn"
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) clearHistory(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Typ string `json:"type"`
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	typeMap := map[string]challtestsrv.RequestEventType{
		"http":    challtestsrv.HTTPRequestEventType,
		"dns":     challtestsrv.DNSRequestEventType,
		"tlsalpn": challtestsrv.TLSALPNRequestEventType,
	}
	if code, ok := typeMap[request.Typ]; ok {
		srv.challSrv.ClearRequestHistory(code)
		srv.log.Printf("Cleared challenge server request history for %q events\n",
			request.Typ)
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, fmt.Sprintf("%q event type unknown", request.Typ), http.StatusBadRequest)
}

// getHTTPHistory returns only the HTTPRequestEvent's from the challenge
// server's request history in JSON form.
func (srv *managementServer) getHTTPHistory(w http.ResponseWriter, r *http.Request) {
	srv.writeHistory(srv.challSrv.RequestHistory(challtestsrv.HTTPRequestEventType), w)
}

// getDNSHistory returns only the DNSRequestEvent's from the challenge
// server's request history in JSON form.
func (srv *managementServer) getDNSHistory(w http.ResponseWriter, r *http.Request) {
	srv.writeHistory(srv.challSrv.RequestHistory(challtestsrv.DNSRequestEventType), w)
}

// getTLSALPNHistory returns only the TLSALPNRequestEvent's from the challenge
// server's request history in JSON form.
func (srv *managementServer) getTLSALPNHistory(w http.ResponseWriter, r *http.Request) {
	srv.writeHistory(srv.challSrv.RequestHistory(challtestsrv.TLSALPNRequestEventType), w)
}

// writeHistory writes the provided list of challtestsrv.RequestEvents to the
// provided http.ResponseWriter in JSON form.
func (srv *managementServer) writeHistory(
	history []challtestsrv.RequestEvent, w http.ResponseWriter) {
	// Always write an empty JSON list instead of `null`
	if history == nil {
		history = []challtestsrv.RequestEvent{}
	}
	jsonHistory, err := json.MarshalIndent(history, "", "   ")
	if err != nil {
		srv.log.Printf("Error marshaling history: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(jsonHistory)
}
