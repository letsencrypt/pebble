package challtestsrv

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// RequestEvent is an interface used to handle disparate request event types in
// a uniform list.
type RequestEvent interface {
	String() string
}

// HTTPRequestEvent corresponds to an HTTP request received by a httpOneServer.
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

// An HTTPRequestEvent is String formatted as:
// <timestamp> - HTTP|HTTPS - <Method> - <Host> - <URL>
func (e HTTPRequestEvent) String() string {
	timeStamp := e.Time.Format(time.RFC3339)
	protocol := "HTTP"
	if e.HTTPS {
		protocol = "HTTPS"
	}
	return fmt.Sprintf("%s - %s - %s - %s - %s", timeStamp, protocol, e.Method, e.Host, e.URL)
}

// DNSRequestEvent corresponds to a DNS request received by a dnsOneServer.
type DNSRequestEvent struct {
	// Time request was received.
	Time time.Time
	// The DNS question received.
	Question dns.Question
}

// A DNSRequestEvent is String formatted as:
// <timestamp> - DNS - "<query>"
func (e DNSRequestEvent) String() string {
	timeStamp := e.Time.Format(time.RFC3339)
	return fmt.Sprintf("%s - DNS - %q", timeStamp, e.Question.String())
}

// TLSALPNRequestEvent corresponds to a TLS request received by
// a tlsALPNOneServer.
type TLSALPNRequestEvent struct {
	// Time request was received.
	Time time.Time
	// ServerName from the TLS Client Hello.
	ServerName string
	// SupportedProtos from the TLS Client Hello.
	SupportedProtos []string
}

// A TLSALPNRequestEvent is String formatted as:
// <timestamp> - TLS-ALPN-01 - <servername> - <comma separated supported protos>
func (e TLSALPNRequestEvent) String() string {
	timeStamp := e.Time.Format(time.RFC3339)
	return fmt.Sprintf("%s - TLS-ALPN-01 - %s - %s",
		timeStamp, e.ServerName, strings.Join(e.SupportedProtos, ","))
}

// AddRequestEvent appends a RequestEvent to the server's request history.
func (s *ChallSrv) AddRequestEvent(event RequestEvent) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	s.requestHistory = append(s.requestHistory, event)
}

// RequestHistory returns the server's request history.
func (s *ChallSrv) RequestHistory() []RequestEvent {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	return s.requestHistory
}

// ClearRequestHistory clears the server's request history.
func (s *ChallSrv) ClearRequestHistory() {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	s.requestHistory = []RequestEvent{}
}
