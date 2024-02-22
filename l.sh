#!/bin/sh

# Fail on error, undefined, and uninitialized variables
set -eu

# Self-check with shellcheck
shellcheck "$0"

# Run golangci-lint but ignore go.work files
GOWORK=off golangci-lint run
