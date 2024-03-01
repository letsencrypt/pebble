#!/bin/sh

# Fail on error, undefined, and uninitialized variables
set -eu

# Build the Go binaries for Linux containers
GOOS="linux" ./build.sh

# Build `pebble` and `pebble-challtestsrv` images
APPS="pebble pebble-challtestsrv"
for APP in ${APPS}; do
    TAG=${APP}:latest
    docker buildx build \
        --build-context dist-files=/tmp/dist \
        --tag "${TAG}" \
        --load \
        --file Dockerfile.release \
        --quiet \
        .
    TAGS="${TAGS-} ${TAG}"
done

set +x
echo "Built Docker image tags:"
for tag in ${TAGS}; do
    echo "  - ${tag}"
done

# Smoke test the release image
echo Docker image runs:
echo '  - ' "$(
    docker run -it --env GOCOVERDIR=/tmp --rm pebble:latest -version
)"
