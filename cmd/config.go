package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

// ReadConfigFile takes a file path as an argument and attempts to
// unmarshal the content of the file into a struct containing a
// configuration of a Pebble component.
//
// Lifted from
//   https://raw.githubusercontent.com/letsencrypt/boulder/master/cmd/shell.go
func ReadConfigFile(filename string, out interface{}) error {
	configData, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(configData, out)
}

// FailOnError exits and prints an error message if we encountered a problem
//
// Lifted from
//   https://raw.githubusercontent.com/letsencrypt/boulder/master/cmd/shell.go
func FailOnError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
	}
}
