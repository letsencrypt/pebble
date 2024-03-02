#!/bin/sh

# Fail on error, undefined, and uninitialized variables
set -eu

# Build the Go binaries for Linux containers
GOOS="linux" ./build.sh

# Build `pebble` and `pebble-challtestsrv` images
APPS="pebble pebble-challtestsrv"
TAG_PREFIX="ghcr.io/letsencrypt"
for APP in ${APPS}; do
    TAG="${TAG_PREFIX}/${APP}:latest"
    docker buildx build \
        --build-arg "APP=${APP}" \
        --build-context dist-files=./dist \
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
    docker run --rm ${TAG_PREFIX}/pebble:latest -version
)"
