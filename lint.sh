#!/bin/sh

# Fail on error, undefined, and uninitialized variables
set -eu

# Self-check with shellcheck
shellcheck "$0"

# Run golangci-lint with the default configuration
# but disable GOWORK to only check local go.mod
GOWORK=off golangci-lint run
