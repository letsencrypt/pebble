package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/letsencrypt/pebble/ca"
	"github.com/letsencrypt/pebble/cmd"
	"github.com/letsencrypt/pebble/db"
	"github.com/letsencrypt/pebble/va"
	"github.com/letsencrypt/pebble/wfe"
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
		// Require External Account Binding for "newAccount" requests
		ExternalAccountBindingRequired bool
		ExternalAccountMACKeys         map[string]string
		// Configure policies to deny certain domains
		DomainBlocklist []string
	}
}

const (
	// vaNoSleepEnvVar and vaSleepTimeEnvVar are deprecated environment variable
	// names used to control sleeping in the VA. Now sleepTimeEnvVar is the proper
	// method to manage it.  Exists for deprecation warning purposes.
	vaNoSleepEnvVar   = "PEBBLE_VA_NOSLEEP"
	vaSleepTimeEnvVar = "PEBBLE_VA_SLEEPTIME"

	// sleepTimeEnvVar is the variable used to control if and how much the process
	// sleeps during specific stages of the workflow. 0 disables sleeping, negative
	// and non-integers will be ignored, and positive integers are the maximum
	// number of seconds to sleep for.
	sleepTimeEnvVar = "PEBBLE_SLEEPTIME"

	// defaultSleepTime defines the default sleep time (in seconds) at various
	// stages in the workflow.
	defaultSleepTime = 5
)

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
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
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

	sleepTime := getEnvSleepTime(logger, os.Getenv(sleepTimeEnvVar), os.Getenv(vaNoSleepEnvVar), os.Getenv(vaSleepTimeEnvVar))
	if sleepTime == 0 {
		logger.Print("Disabled random sleeps")
	} else {
		logger.Printf("Setting maximum random sleep interval to %d seconds", sleepTime)
	}

	db := db.NewMemoryStore()
	ca := ca.New(logger, db, c.Pebble.OCSPResponderURL, alternateRoots, chainLength, sleepTime)
	va := va.New(logger, c.Pebble.HTTPPort, c.Pebble.TLSPort, *strictMode, *resolverAddress, sleepTime)

	for keyID, key := range c.Pebble.ExternalAccountMACKeys {
		err := db.AddExternalAccountKeyByID(keyID, key)
		cmd.FailOnError(err, "Failed to add key to external account bindings")
	}

	for _, domainName := range c.Pebble.DomainBlocklist {
		err := db.AddBlockedDomain(domainName)
		cmd.FailOnError(err, "Failed to add domain to block list")
	}

	wfeImpl := wfe.New(logger, db, va, ca, *strictMode, c.Pebble.ExternalAccountBindingRequired)
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

// getEnvSleepTime is the abstraction to decide how long to randomly sleep for. This is
// relatively verbose, due to handling the deprecated PEBBLE_VA_* sleep methods.  Most
// of this can be removed after a suitable transition period. The deprecated path is not
// documented.
func getEnvSleepTime(logger *log.Logger, envSleepTime string, envVaNoSleep string, envVaSleepTime string) int {
	sleepTime, vaSleepTime, vaNoSleep := parseSleepEnvironment(logger, envSleepTime, envVaNoSleep, envVaSleepTime)

	if sleepTime < 0 && !vaNoSleep && vaSleepTime < 0 { // 1
		return defaultSleepTime
	} else if sleepTime >= 0 && !vaNoSleep && vaSleepTime < 0 { // 2
		return sleepTime
	} else if sleepTime < 0 && !vaNoSleep && vaSleepTime >= 0 { // 3
		return vaSleepTime
	} else if sleepTime >= 0 && !vaNoSleep && vaSleepTime >= 0 { // 4
		logger.Printf("WARNING: %s is present with %s, ignoring %s", sleepTimeEnvVar, vaSleepTimeEnvVar, vaSleepTimeEnvVar)
		return sleepTime
	} else if sleepTime < 0 && vaNoSleep && vaSleepTime < 0 { // 5
		return 0
	} else if sleepTime >= 0 && vaNoSleep && vaSleepTime < 0 { // 6
		logger.Printf("WARNING: %s is present with %s, ignoring %s", sleepTimeEnvVar, vaNoSleepEnvVar, vaNoSleepEnvVar)
		return sleepTime
	} else if sleepTime < 0 && vaNoSleep && vaSleepTime >= 0 { // 7
		logger.Printf("WARNING: %s is present with %s, ignoring %s", vaNoSleepEnvVar, vaSleepTimeEnvVar, vaSleepTimeEnvVar)
		return 0
	} else /*if sleepTime >= 0 && vaNoSleep && vaSleepTime >= 0*/ { // 8
		logger.Printf("WARNING: %s is present with %s and %s, ignoring %s and %s", sleepTimeEnvVar, vaNoSleepEnvVar, vaSleepTimeEnvVar, vaNoSleepEnvVar, vaSleepTimeEnvVar)
		return sleepTime
	}
}

// parseSleepEnvironment exists to make the linter happy.  When PEBBLE_VA_* is removed,
// whatever remains of this function should be merged with getEnvSleepTime.
func parseSleepEnvironment(logger *log.Logger, envSleepTime string, envVaNoSleep string, envVaSleepTime string) (int, int, bool) {
	sleepTime := -1
	if envSleepTime != "" {
		i, err := strconv.ParseUint(envSleepTime, 10, 64) // Uint parse makes negatives fail
		if err != nil {
			logger.Printf("WARNING: Failed to parse %s", sleepTimeEnvVar)
		} else {
			sleepTime = int(i)
		}
	}

	vaSleepTime := -1
	if envVaSleepTime != "" {
		logger.Printf("WARNING: %s is deprecated, use %s=%s", vaSleepTimeEnvVar, sleepTimeEnvVar, envVaSleepTime)
		i, err := strconv.ParseUint(envVaSleepTime, 10, 64) // Uint parse makes negatives fail
		if err != nil {
			logger.Printf("WARNING: Failed to parse %s", vaSleepTimeEnvVar)
		} else {
			vaSleepTime = int(i)
		}
	}

	vaNoSleep := false
	if envVaNoSleep != "" {
		logger.Printf("WARNING: %s is deprecated, use %s=0", vaNoSleepEnvVar, sleepTimeEnvVar)
	}
	switch strings.ToLower(envVaNoSleep) {
	case "1", "true":
		vaNoSleep = true
	case "0", "false", "":
		// no action
	default:
		logger.Printf("WARNING: Failed to parse %s", vaNoSleepEnvVar)
	}
	return sleepTime, vaSleepTime, vaNoSleep
}
