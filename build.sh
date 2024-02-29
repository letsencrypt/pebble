#!/bin/sh -x

# Fail on error, undefined, and uninitialized variables
set -eu

# Set Go build tags from command line arguments, if any.
TAGS=${*:-''}

# Set Go build environment variables, if not already set.
export GOARCH="${GOARCH:-$(go env GOARCH)}"
export GOOS="${GOOS:-$(go env GOOS)}"

# Build output
OUTPUT="dist/${GOOS}/${GOARCH}/"

# Run the Go tests with coverage and race detection.
# Enable cgo for race detection in cross compilation.
export CGO_ENABLED=1
go build \
    -cover \
    -o="${OUTPUT}" \
    -race \
    -tags="${TAGS}" \
    -v \
    ./...
