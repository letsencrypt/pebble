package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/letsencrypt/pebble/ca"
	"github.com/letsencrypt/pebble/cmd"
	"github.com/letsencrypt/pebble/db"
	"github.com/letsencrypt/pebble/va"
	"github.com/letsencrypt/pebble/wfe"
)

type config struct {
	Pebble struct {
		ListenAddress string
		HTTPPort      int
		TLSPort       int
		Certificate   string
		PrivateKey    string
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
	ocspResponder := flag.String(
		"ocspresponder",
		"",
		"Define an OCSP responder URL to put in the 1.3.6.1.5.5.7.48.1 field of an issued certificate.")
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

	if len(*resolverAddress) > 0 {
		setupCustomDNSResolver(*resolverAddress)
	}

	db := db.NewMemoryStore()
	ca := ca.New(logger, db, *ocspResponder)
	va := va.New(logger, c.Pebble.HTTPPort, c.Pebble.TLSPort, *strictMode)

	wfeImpl := wfe.New(logger, db, va, ca, *strictMode)
	muxHandler := wfeImpl.Handler()

	logger.Printf("Listening on: %s\n", c.Pebble.ListenAddress)
	logger.Printf("ACME directory available at: https://%s%s",
		c.Pebble.ListenAddress, wfe.DirectoryPath)
	logger.Printf("Root CA certificate available at: https://%s%s",
		c.Pebble.ListenAddress, wfe.RootCertPath)
	err = http.ListenAndServeTLS(
		c.Pebble.ListenAddress,
		c.Pebble.Certificate,
		c.Pebble.PrivateKey,
		muxHandler)
	cmd.FailOnError(err, "Calling ListenAndServeTLS()")
}

func setupCustomDNSResolver(dnsResolverAddress string) {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", dnsResolverAddress)
		},
	}
}
