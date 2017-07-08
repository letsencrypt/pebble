package core

import (
	"encoding/json"
	"io/ioutil"
)

type Config struct {
	Pebble struct {
		ListenAddress string
		HTTPPort      int
		TLSPort       int
	}
}

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
