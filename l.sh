#!/bin/sh

# Fail on error, undefined, and uninitialized variables
set -eu

# Self-check with shellcheck
shellcheck "$0"

# Disable GOWORK for local-only module maintenance
export GOWORK=off

# Tidy up the go.mod file and download/vendor dependencies.
# Check for changes to the go.mod and go.sum files and vendor directory.
go mod tidy -v -x
git diff --exit-code go.mod
git diff --exit-code go.sum
go mod vendor -v
git diff --exit-code vendor

# Run golangci-lint
golangci-lint run
