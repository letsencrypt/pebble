#!/bin/sh

# Fail on error, undefined, and uninitialized variables
set -eu

APPS="pebble pebble-challtestsrv"

# no context needed for dev container
docker buildx build \
    --tag pebble:dev \
    --load \
    --quiet \
    - <Dockerfile.devcontainer

docker run --rm \
    --env GOCACHE=/.cache/go-build \
    --volume "$(pwd)":/work \
    --volume "$(go env GOCACHE)":/.cache/go-build:cached \
    --volume /tmp/dist:/work/dist \
    --workdir /work \
    pebble:dev \
    "./build.sh"

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
echo "Built tags:"
for tag in ${TAGS}; do
    echo "  - ${tag}"
done

# Smoke test the release image
echo Docker installed:
echo '  - ' "$(
    docker run -it --env GOCOVERDIR=/tmp --rm pebble:latest -version
)"
