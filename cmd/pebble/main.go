package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/cmd"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
)

var version = "dev" // Default value, to be overridden with ldflags

// CRL settings, in seconds.
const (
	defaultCRLMaxDelay = 15
	defaultCRLValidity = 7 * 24 * 60 * 60
	maxCRLValidity     = 10 * 24 * 60 * 60
)

type config struct {
	Pebble struct {
		ListenAddress           string
		ManagementListenAddress string
		HTTPPort                int
		TLSPort                 int
		Certificate             string
		PrivateKey              string
		OCSPResponderURL        string
		// Optional CRL support, enabled only when both CRLListenAddress and
		// CRLBaseURL are set.
		CRLListenAddress string
		CRLBaseURL       string
		// Maximum random delay in seconds before a revocation appears on the
		// CRL. Unset means defaultCRLMaxDelay, and 0 means no delay.
		CRLMaxDelay *int
		// Seconds from thisUpdate to nextUpdate. 0 means defaultCRLValidity.
		CRLValidity int
		// Require External Account Binding for "newAccount" requests
		ExternalAccountBindingRequired bool
		ExternalAccountMACKeys         map[string]string
		CAAIdentities                  []string
		// Configure policies to deny certain domains
		DomainBlocklist []string
		KeyAlgorithm    string
		Profiles        map[string]ca.Profile

		RetryAfter struct {
			Authz int
			Order int
		}

		// Deprecated: use Profiles.ValidityPeriod instead
		CertificateValidityPeriod uint64
	}
}

func main() {
	configFile := flag.String(
		"config",
		"test/config/pebble-config.json",
		"File path to the Pebble configuration file")
	strictMode := flag.Bool(
		"strict",
		false,
		"Enable strict mode to test upcoming API breaking changes")
	resolverAddress := flag.String(
		"dnsserver",
		"",
		"Define a custom DNS server address (ex: 192.168.0.56:5053 or 8.8.8.8:53).")
	versionFlag := flag.Bool(
		"version",
		false,
		"Print the software version")
	flag.Parse()

	if len(flag.Args()) > 0 {
		fmt.Printf("invalid command line arguments: %s\n", strings.Join(flag.Args(), " "))
		flag.Usage()
		os.Exit(1)
	}

	if *versionFlag {
		// Print the version and exit
		fmt.Printf("Pebble version: %s\n", version)
		os.Exit(0)
	}

	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	if *strictMode {
		fmt.Printf("Running in strict mode\n")
	}

	// Log to stdout
	logger := log.New(os.Stdout, "Pebble ", log.LstdFlags)
	logger.Printf("Starting Pebble ACME server")

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	alternateRoots := 0
	alternateRootsVal := os.Getenv("PEBBLE_ALTERNATE_ROOTS")
	if val, err := strconv.ParseInt(alternateRootsVal, 10, 0); err == nil && val >= 0 {
		alternateRoots = int(val)
	}

	chainLength := 1
	if val, err := strconv.ParseInt(os.Getenv("PEBBLE_CHAIN_LENGTH"), 10, 0); err == nil && val >= 0 {
		chainLength = int(val)
	}

	keyAlg := c.Pebble.KeyAlgorithm
	if keyAlg == "" {
		keyAlg = "rsa"
	}
	acceptableKeyAlgs := []string{"rsa", "ecdsa"}
	if !slices.Contains(acceptableKeyAlgs, keyAlg) {
		cmd.FailOnError(fmt.Errorf("%q is not one of %#v", keyAlg, acceptableKeyAlgs), "invalid key algorithm")
	}

	profiles := c.Pebble.Profiles
	if len(profiles) == 0 {
		profiles = map[string]ca.Profile{
			"default": {
				Description:    "The default profile",
				ValidityPeriod: 0, // Will be overridden by the CA's default
			},
		}
	}

	crlConfig, err := loadCRLConfig(&c, logger)
	cmd.FailOnError(err, "Invalid CRL configuration")

	db := db.NewMemoryStore()
	ca := ca.New(logger, db, c.Pebble.OCSPResponderURL, keyAlg, alternateRoots, chainLength, profiles, crlConfig)
	va := va.New(logger, c.Pebble.HTTPPort, c.Pebble.TLSPort, *strictMode, *resolverAddress, db)

	for keyID, key := range c.Pebble.ExternalAccountMACKeys {
		err := db.AddExternalAccountKeyByID(keyID, key)
		cmd.FailOnError(err, "Failed to add key to external account bindings")
	}

	for _, domainName := range c.Pebble.DomainBlocklist {
		err := db.AddBlockedDomain(domainName)
		cmd.FailOnError(err, "Failed to add domain to block list")
	}

	if len(c.Pebble.CAAIdentities) < 1 {
		logger.Println("No CAA identities configured, using default [pebble.letsencrypt.org]")
		c.Pebble.CAAIdentities = []string{"pebble.letsencrypt.org"}
	}

	wfeImpl := wfe.New(logger, db, va, ca, c.Pebble.CAAIdentities, *strictMode, c.Pebble.ExternalAccountBindingRequired, c.Pebble.RetryAfter.Authz, c.Pebble.RetryAfter.Order)
	muxHandler := wfeImpl.Handler()

	if c.Pebble.ManagementListenAddress != "" {
		go func() {
			adminHandler := wfeImpl.ManagementHandler()
			err = http.ListenAndServeTLS(
				c.Pebble.ManagementListenAddress,
				c.Pebble.Certificate,
				c.Pebble.PrivateKey,
				adminHandler)
			cmd.FailOnError(err, "Calling ListenAndServeTLS() for admin interface")
		}()
		logger.Printf("Management interface listening on: %s\n", c.Pebble.ManagementListenAddress)
		logger.Printf("Root CA certificate available at: https://%s%s0",
			c.Pebble.ManagementListenAddress, wfe.RootCertPath)
		for i := 0; i < alternateRoots; i++ {
			logger.Printf("Alternate (%d) root CA certificate available at: https://%s%s%d",
				i+1, c.Pebble.ManagementListenAddress, wfe.RootCertPath, i+1)
		}
	} else {
		logger.Print("Management interface is disabled")
	}

	if crlConfig != nil {
		go func() {
			err := http.ListenAndServe(c.Pebble.CRLListenAddress, wfeImpl.CRLHandler())
			cmd.FailOnError(err, "Calling ListenAndServe() for CRL interface")
		}()
		logger.Printf("CRL interface listening on: %s\n", c.Pebble.CRLListenAddress)
		logger.Printf("CRL available at: %s", ca.CRLURL())
	} else {
		logger.Print("CRL interface is disabled")
	}

	logger.Printf("Listening on: %s\n", c.Pebble.ListenAddress)
	logger.Printf("ACME directory available at: https://%s%s",
		c.Pebble.ListenAddress, wfe.DirectoryPath)
	err = http.ListenAndServeTLS(
		c.Pebble.ListenAddress,
		c.Pebble.Certificate,
		c.Pebble.PrivateKey,
		muxHandler)
	cmd.FailOnError(err, "Calling ListenAndServeTLS()")
}

// envInt returns the value of an integer environment variable, or nil if it's
// unset or not an integer. A non-integer value is logged.
func envInt(name string, logger *log.Logger) *int {
	val, ok := os.LookupEnv(name)
	if !ok {
		return nil
	}
	parsed, err := strconv.ParseInt(val, 10, 0)
	if err != nil {
		logger.Printf("Ignoring %s=%q: not an integer", name, val)
		return nil
	}
	i := int(parsed)
	return &i
}

// loadCRLConfig combines the CRL config fields with their PEBBLE_CRL_*
// environment overrides, validates them, and returns the CA's CRL
// configuration, or nil if CRLs are disabled. It also writes the effective
// listen address back to c.Pebble.CRLListenAddress.
func loadCRLConfig(c *config, logger *log.Logger) (*ca.CRLConfig, error) {
	if val := os.Getenv("PEBBLE_CRL_LISTEN_ADDRESS"); val != "" {
		c.Pebble.CRLListenAddress = val
	}
	if val := os.Getenv("PEBBLE_CRL_BASE_URL"); val != "" {
		c.Pebble.CRLBaseURL = val
	}

	maxDelay := defaultCRLMaxDelay
	if c.Pebble.CRLMaxDelay != nil {
		maxDelay = *c.Pebble.CRLMaxDelay
	}
	if val := envInt("PEBBLE_CRL_MAX_DELAY", logger); val != nil {
		maxDelay = *val
	}

	validity := c.Pebble.CRLValidity
	if val := envInt("PEBBLE_CRL_VALIDITY", logger); val != nil {
		validity = *val
	}

	listen, base := c.Pebble.CRLListenAddress, c.Pebble.CRLBaseURL
	if listen == "" && base == "" {
		return nil, nil
	}
	if listen == "" || base == "" {
		return nil, errors.New("crlListenAddress and crlBaseURL must be set together")
	}

	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parsing crlBaseURL %q: %w", base, err)
	}
	if u.Scheme != "http" || u.Host == "" {
		return nil, fmt.Errorf("crlBaseURL %q must be an absolute http:// URL", base)
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	if maxDelay < 0 {
		return nil, fmt.Errorf("crlMaxDelay must not be negative: %d", maxDelay)
	}

	switch {
	case validity < 0:
		return nil, fmt.Errorf("crlValidity must not be negative: %d", validity)
	case validity == 0:
		validity = defaultCRLValidity
	case validity > maxCRLValidity:
		logger.Printf("crlValidity of %d seconds exceeds 10 days, using %d", validity, maxCRLValidity)
		validity = maxCRLValidity
	}

	return &ca.CRLConfig{
		BaseURL:  base,
		MaxDelay: int64(maxDelay),
		Validity: time.Duration(validity) * time.Second,
	}, nil
}
