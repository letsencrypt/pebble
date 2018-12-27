#!/usr/bin/env bash
set -e

if [[ "${TRAVIS_PULL_REQUEST}" = "false" ]]; then
    echo "Publishing..."
else
    echo "Skipping publishing"
    exit 0
fi

docker login -u $DOCKER_USER -p $DOCKER_PASS

BASE_NAMES=(pebble pebble-challtestsrv)
for BASE_NAME in ${BASE_NAMES[@]}; do
    IMAGE_NAME="letsencrypt/${BASE_NAME}"

    echo "Updating docker ${IMAGE_NAME} image..."

    # create docker image
    docker build -t ${IMAGE_NAME}:latest -f docker/${BASE_NAME}/Dockerfile .

    # push images
    echo "Try to publish image: ${IMAGE_NAME}:latest"
    docker push ${IMAGE_NAME}:latest

    if [[ -n "$TRAVIS_COMMIT" ]]; then
        echo "Try to publish image: ${IMAGE_NAME}:${TRAVIS_COMMIT}"
        docker tag ${IMAGE_NAME}:latest ${IMAGE_NAME}:${TRAVIS_COMMIT}
        docker push ${IMAGE_NAME}:${TRAVIS_COMMIT}
    fi

    if [[ -n "${TRAVIS_TAG}" ]]; then
        echo "Try to publish image: ${IMAGE_NAME}:${TRAVIS_TAG}"
        docker tag ${IMAGE_NAME}:latest ${IMAGE_NAME}:${TRAVIS_TAG}
        docker push ${IMAGE_NAME}:${TRAVIS_TAG}
    fi
done

echo "Published"