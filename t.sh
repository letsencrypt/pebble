#!/bin/sh

# Fail on error, undefined, and uninitialized variables
set -eu

# Self-check with shellcheck
shellcheck "$0"

# Run the Go tests in a container
# Building for race tests requires cgo
docker run --rm -e CGO_ENABLED=1 \
    --volume "$(pwd):/go/src/github.com/letsencrypt/pebble" \
    --workdir /go/src/github.com/letsencrypt/pebble \
    golang:1-alpine \
    sh -c "apk add build-base && go test -v -race ./..."

# Run the integration tests in containers
docker compose \
    --file docker-compose.yml \
    --file test/integration-compose.yml \
    run --build --rm --use-aliases integration \
    make ACME_DIRECTORY=https://pebble:14000/dir CLIENT=pebble test

# Clean up test containers and volumes
docker compose down --volumes
