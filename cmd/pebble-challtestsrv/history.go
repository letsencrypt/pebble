package main

import (
	"encoding/json"
	"net/http"

	"github.com/letsencrypt/challtestsrv"
)

// clearHistory handles an HTTP POST request to clear the challenge server
// request history.
//
// The POST body is expected to be the trivial JSON payload `{}`
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) clearHistory(w http.ResponseWriter, r *http.Request) {
	var request struct{}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	srv.challSrv.ClearRequestHistory()
	srv.log.Print("Cleared challenge server request history\n")
	w.WriteHeader(http.StatusOK)
}

// getHTTPHistory returns only the HTTPRequestEvent's from the challenge
// server's request history in JSON form.
func (srv *managementServer) getHTTPHistory(w http.ResponseWriter, r *http.Request) {
	history := srv.challSrv.RequestHistory()

	var filteredHistory []challtestsrv.RequestEvent
	for _, event := range history {
		if httpEvent, ok := event.(challtestsrv.HTTPRequestEvent); ok {
			filteredHistory = append(filteredHistory, httpEvent)
		}
	}

	srv.writeHistory(filteredHistory, w)
}

// getDNSHistory returns only the DNSRequestEvent's from the challenge
// server's request history in JSON form.
func (srv *managementServer) getDNSHistory(w http.ResponseWriter, r *http.Request) {
	history := srv.challSrv.RequestHistory()

	var filteredHistory []challtestsrv.RequestEvent
	for _, event := range history {
		if dnsEvent, ok := event.(challtestsrv.DNSRequestEvent); ok {
			filteredHistory = append(filteredHistory, dnsEvent)
		}
	}

	srv.writeHistory(filteredHistory, w)
}

// getTLSALPNHistory returns only the TLSALPNRequestEvent's from the challenge
// server's request history in JSON form.
func (srv *managementServer) getTLSALPNHistory(w http.ResponseWriter, r *http.Request) {
	history := srv.challSrv.RequestHistory()

	var filteredHistory []challtestsrv.RequestEvent
	for _, event := range history {
		if alpnEvent, ok := event.(challtestsrv.TLSALPNRequestEvent); ok {
			filteredHistory = append(filteredHistory, alpnEvent)
		}
	}

	srv.writeHistory(filteredHistory, w)
}

// writeHistory writes the provided list of challtestsrv.RequestEvents to the
// provided http.ResponseWriter in JSON form.
func (srv *managementServer) writeHistory(
	history []challtestsrv.RequestEvent, w http.ResponseWriter) {
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
