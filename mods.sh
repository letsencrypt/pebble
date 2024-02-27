#!/bin/sh

# Fail on error, undefined, and uninitialized variables
set -eu

# Self-check with shellcheck
shellcheck "$0"

# Disable GOWORK for local-only module maintenance
export GOWORK=off

# Tidy up the go.mod file and vendored dependencies.
# Check for changes to the go.mod and go.sum files or the vendor directory.
go mod tidy -v -x
git diff --exit-code go.mod
git diff --exit-code go.sum
go mod vendor
git diff --exit-code vendor
