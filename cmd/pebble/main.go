package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/letsencrypt/pebble/cmd"
	"github.com/letsencrypt/pebble/wfe"
)

type config struct {
	Pebble struct {
		ListenAddress string
	}
}

func main() {
	configFile := flag.String(
		"config",
		"test/config/pebble-config.json",
		"File path to the Pebble configuration file")
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

	wfe, err := wfe.New(logger)
	muxHandler := wfe.Handler()

	srv := &http.Server{
		Addr:    c.Pebble.ListenAddress,
		Handler: muxHandler,
	}

	logger.Printf("Pebble running, listening on: %s\n", c.Pebble.ListenAddress)
	err = srv.ListenAndServe()
	cmd.FailOnError(err, "Calling ListenAndServe()")
}
