package challtestsrv

import (
	"time"

	"github.com/miekg/dns"
)

// RequestEventType indicates what type of event occurred.
type RequestEventType int

const (
	// HTTP requests
	HTTPRequestEventType RequestEventType = iota
	// DNS requests
	DNSRequestEventType
	// TLS-ALPN-01 requests
	TLSALPNRequestEventType
)

// A RequestEvent is anything that can identify its RequestEventType
type RequestEvent interface {
	Type() RequestEventType
}

// HTTPRequestEvent corresponds to an HTTP request received by a httpOneServer.
// It implements the RequestEvent interface.
type HTTPRequestEvent struct {
	// Time the request was received
	Time time.Time
	// The full request URL (path and query arguments)
	URL string
	// The Host header from the request
	Host string
	// The request Method (POST, GET, HEAD, etc)
	Method string
	// The request path
	Path string
	// Whether the request was received over HTTPS or HTTP
	HTTPS bool
	// The ServerName from the ClientHello. May be empty if there was no SNI or if
	// the request was not HTTPS
	ServerName string
}

// HTTPRequestEvents always have type HTTPRequestEventType
func (e HTTPRequestEvent) Type() RequestEventType {
	return HTTPRequestEventType
}

// DNSRequestEvent corresponds to a DNS request received by a dnsOneServer. It
// implements the RequestEvent interface.
type DNSRequestEvent struct {
	// Time request was received.
	Time time.Time
	// The DNS question received.
	Question dns.Question
}

// DNSRequestEvents always have type DNSRequestEventType
func (e DNSRequestEvent) Type() RequestEventType {
	return DNSRequestEventType
}

// TLSALPNRequestEvent corresponds to a TLS request received by
// a tlsALPNOneServer. It implements the RequestEvent interface.
type TLSALPNRequestEvent struct {
	// Time request was received.
	Time time.Time
	// ServerName from the TLS Client Hello.
	ServerName string
	// SupportedProtos from the TLS Client Hello.
	SupportedProtos []string
}

// TLSALPNRequestEvents always have type TLSALPNRequestEventType
func (e TLSALPNRequestEvent) Type() RequestEventType {
	return TLSALPNRequestEventType
}

// AddRequestEvent adds a RequestEvent to the server's request history. It is
// appeneded to a list of RequestEvents indexed by the event's Type().
func (s *ChallSrv) AddRequestEvent(event RequestEvent) {
	s.challMu.Lock()
	defer s.challMu.Unlock()

	typ := event.Type()
	s.requestHistory[typ] = append(s.requestHistory[typ], event)
}

// RequestHistory returns the server's request history for the given event type.
func (s *ChallSrv) RequestHistory(typ RequestEventType) []RequestEvent {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	return s.requestHistory[typ]
}

// ClearRequestHistory clears the server's request history for the given event
// type.
func (s *ChallSrv) ClearRequestHistory(typ RequestEventType) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	s.requestHistory[typ] = []RequestEvent{}
}
