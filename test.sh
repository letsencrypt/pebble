#!/bin/sh -x
# This script runs standalone tests.

# Fail on error, undefined, and uninitialized variables
set -eu

# Self-check with shellcheck
shellcheck "$0"

# Set Go build tags from command line arguments, if any.
TAGS=${*:-''}

# Run the Go tests with coverage and race detection.
# Enable cgo and disable Go workspaces.
export CGO_ENABLED=1
export GOWORK=off
go test \
    -coverprofile=profile.cov \
    -race \
    -tags="${TAGS}" \
    -v \
    ./...
