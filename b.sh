#!/bin/sh -x

# Fail on error, undefined, and uninitialized variables
set -eu

# Disable GOWORK for local module maintenance
export GOWORK=off

# Tidy up the go.mod file and download/vendor dependencies
# Check for changes to the go.mod and go.sum files and vendor directory
go mod tidy
git diff --exit-code go.mod
git diff --exit-code go.sum
go mod download
go mod vendor
git diff --exit-code vendor

# Build the project
go build -v -mod=vendor ./...
