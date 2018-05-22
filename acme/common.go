package acme

// acme.Resource values identify different types of ACME resources
type Resource string

const (
	StatusPending     = "pending"
	StatusInvalid     = "invalid"
	StatusValid       = "valid"
	StatusExpired     = "expired"
	StatusProcessing  = "processing"
	StatusReady       = "ready"
	StatusDeactivated = "deactivated"

	IdentifierDNS = "dns"

	ChallengeHTTP01    = "http-01"
	ChallengeTLSALPN01 = "tls-alpn-01"
	ChallengeDNS01     = "dns-01"

	HTTP01BaseURL = ".well-known/acme-challenge/"

	ACMETLS1Protocol = "acme-tls/1"
)

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Account struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact"`
	Orders  string   `json:"orders,omitempty"`
}

// An Order is created to request issuance for a CSR
type Order struct {
	Status         string          `json:"status"`
	Error          *ProblemDetails `json:"error,omitempty"`
	Expires        string          `json:"expires"`
	Identifiers    []Identifier    `json:"identifiers,omitempty"`
	Finalize       string          `json:"finalize"`
	NotBefore      string          `json:"notBefore,omitempty"`
	NotAfter       string          `json:"notAfter,omitempty"`
	Authorizations []string        `json:"authorizations"`
	Certificate    string          `json:"certificate,omitempty"`
}

// An Authorization is created for each identifier in an order
type Authorization struct {
	Status     string       `json:"status"`
	Identifier Identifier   `json:"identifier"`
	Challenges []*Challenge `json:"challenges"`
	Expires    string       `json:"expires"`
	// Wildcard is a Let's Encrypt specific Authorization field that indicates the
	// authorization was created as a result of an order containing a name with
	// a `*.`wildcard prefix. This will help convey to users that an
	// Authorization with the identifier `example.com` and one DNS-01 challenge
	// corresponds to a name `*.example.com` from an associated order.
	Wildcard bool `json:"wildcard,omitempty"`
}

// A Challenge is used to validate an Authorization
type Challenge struct {
	Type      string          `json:"type"`
	URL       string          `json:"url"`
	Token     string          `json:"token"`
	Status    string          `json:"status"`
	Validated string          `json:"validated,omitempty"`
	Error     *ProblemDetails `json:"error,omitempty"`
}
