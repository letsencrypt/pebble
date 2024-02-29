#!/bin/sh

# Run shellcheck
shellcheck ./*.sh

# Run golangci-lint with the default configuration
# but disable GOWORK to only check local go.mod
GOWORK=off golangci-lint run
