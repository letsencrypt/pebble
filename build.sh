#!/bin/sh

# Fail on error, undefined, and uninitialized variables
set -eu

# Set Go build tags from command line arguments, if any.
tags=${*:-''}

# Define the software version
version=$(git describe --tags --always --dirty || echo 'unknown')
ldflags="-X main.version=${version}"

# Set Go build environment variables, if not already set.
export GOARCH="${GOARCH:-$(go env GOARCH)}"
export GOOS="${GOOS:-$(go env GOOS)}"

# Build output directory
outputdir="dist/${GOOS}/${GOARCH}"

# Run the Go tests with coverage and race detection.
# Enable cgo for race detection in cross compilation.
export CGO_ENABLED=1
go build \
    -cover \
    -ldflags="${ldflags}" \
    -o="${outputdir}/" \
    -race \
    -tags="${tags}" \
    ./...

echo Go built:
echo '  - ' "$(GOCOVERDIR=/tmp ./"${outputdir}"/pebble -version)"
