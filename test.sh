#!/bin/sh -x

# Fail on error, undefined, and uninitialized variables
set -eu

# Set Go build tags from command line arguments, if any.
TAGS=${*:-''}

# Run the Go tests with coverage and race detection.
go test \
    -coverprofile=profile.cov \
    -race \
    -tags="${TAGS}" \
    -v \
    ./...
