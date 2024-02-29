#!/bin/sh -x

# Fail on error, undefined, and uninitialized variables
set -eu

APPS="pebble pebble-challtestsrv"

# no context needed for dev container
docker buildx build \
    --tag pebble:dev \
    --load \
    --progress plain \
    - <Dockerfile.devcontainer

docker run --rm \
    --env GOCACHE=/work/.cache/go-build \
    --volume "$(pwd)":/work \
    --volume "$(go env GOCACHE)":/work/.cache/go-build \
    --workdir /work \
    pebble:dev \
    "./build.sh"

for APP in ${APPS}; do
    TAG=${APP}:latest
    docker buildx build \
        --build-context dist-files=./dist \
        --tag "${TAG}" \
        --load \
        --file Dockerfile.release \
        --progress plain \
        .
    TAGS="${TAGS-} ${TAG}"
done

set +x
echo "Built tags:"
for tag in ${TAGS}; do
    echo "  - ${tag}"
done

# Smoke test the release image
docker run \
    -it \
    --env GOCOVERDIR=. \
    --rm pebble:latest -version
