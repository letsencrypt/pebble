package cmd

import (
	"fmt"
	"os"
)

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
