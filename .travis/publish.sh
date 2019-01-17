#!/usr/bin/env bash
set -e

if [[ "${TRAVIS_PULL_REQUEST}" = "false" ]]; then
    echo "Publishing..."
else
    echo "Skipping publishing"
    exit 0
fi

docker login -u "$DOCKER_USER" -p "$DOCKER_PASS"

BASE_NAMES=(pebble pebble-challtestsrv)
for BASE_NAME in "${BASE_NAMES[@]}"; do
    IMAGE_NAME="letsencrypt/${BASE_NAME}"

    echo "Updating docker ${IMAGE_NAME} image..."

    # create docker image
    docker build -t "${IMAGE_NAME}:temp" -f "docker/${BASE_NAME}/Dockerfile" .

    # push images
    if [[ -n "${TRAVIS_TAG}" ]]; then
        echo "Try to publish image: ${IMAGE_NAME}:${TRAVIS_TAG}"
        docker tag "${IMAGE_NAME}:temp" "${IMAGE_NAME}:${TRAVIS_TAG}"
        docker push "${IMAGE_NAME}:${TRAVIS_TAG}"

        echo "Try to publish image: ${IMAGE_NAME}:latest"
        docker tag "${IMAGE_NAME}:${TRAVIS_TAG}" "${IMAGE_NAME}:latest"
        docker push "${IMAGE_NAME}:latest"
    fi
done

echo "Published"
