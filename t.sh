#!/bin/sh

# Fail on error, undefined, and uninitialized variables
set -eu

# Self-check with shellcheck
shellcheck "$0"

# Run the integration tests in containers
docker compose \
    --file docker-compose.yml \
    --file test/integration-compose.yml \
    run --build --rm --use-aliases integration \
    make ACME_DIRECTORY=https://pebble:14000/dir CLIENT=pebble test

# Clean up test containers and volumes
docker compose down --volumes
