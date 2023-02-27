package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// ReadConfigFile takes a file path as an argument and attempts to
// unmarshal the content of the file into a struct containing a
// configuration of a Pebble component.
//
// Lifted from
//
//	https://raw.githubusercontent.com/letsencrypt/boulder/master/cmd/shell.go
func ReadConfigFile(filename string, out interface{}) error {
	configData, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(configData, out)
}

// FailOnError exits and prints an error message if we encountered a problem
//
// Lifted from
//
//	https://raw.githubusercontent.com/letsencrypt/boulder/master/cmd/shell.go
func FailOnError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
	}
}

// CatchSignals catches SIGTERM, SIGINT, SIGHUP and executes a callback
// method before exiting
func CatchSignals(callback func()) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	signal.Notify(sigChan, syscall.SIGINT)
	signal.Notify(sigChan, syscall.SIGHUP)

	<-sigChan
	if callback != nil {
		callback()
	}

	os.Exit(0)
}
