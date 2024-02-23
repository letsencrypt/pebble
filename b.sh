#!/bin/sh

# Fail on error, undefined, and uninitialized variables
set -eu

# Build the project
go build -v -mod=vendor ./...
