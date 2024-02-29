#!/bin/sh

# Fail on error, undefined, and uninitialized variables
set -eu

# Run shellcheck
shellcheck *.sh

# Run golangci-lint with the default configuration
# but disable GOWORK to only check local go.mod
GOWORK=off golangci-lint run
