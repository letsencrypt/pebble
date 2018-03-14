package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/jmhodges/clock"
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
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Log to stdout
	logger := log.New(os.Stdout, "Pebble ", log.LstdFlags)

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	clk := clock.Default()
	db := db.NewMemoryStore()
	ca := ca.New(logger, db)
	va := va.New(logger, clk, c.Pebble.HTTPPort, c.Pebble.TLSPort)

	wfe := wfe.New(logger, clk, db, va, ca, *strictMode)
	muxHandler := wfe.Handler()

	logger.Printf("Pebble running, listening on: %s\n", c.Pebble.ListenAddress)
	err = http.ListenAndServeTLS(
		c.Pebble.ListenAddress,
		c.Pebble.Certificate,
		c.Pebble.PrivateKey,
		muxHandler)
	cmd.FailOnError(err, "Calling ListenAndServeTLS()")
}
