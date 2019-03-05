$ErrorActionPreference = 'Stop'
if ($env:APPVEYOR_REPO_TAG -ne "true") {
    "Skipping publishing because this is not a tagged commit"
} else {
    "Publishing the tagged commit..."

    $ErrorActionPreference = 'SilentlyContinue'
    docker login -u="$env:DOCKER_USER" -p="$env:DOCKER_PASS"
    $ErrorActionPreference = 'Stop'

    $basenames = @("pebble", "pebble-challtestsrv")
    foreach ($basename in $basenames) {
        $image_name = "letsencrypt/$basename"
        $tag = "$env:APPVEYOR_REPO_TAG_NAME-nanoserver-sac2016"

        "Updating docker $basename image ..."

        docker build -t="$image_name`:temp" -f="docker/$basename/windows.Dockerfile" .

        "Try to publish image: $image_name`:$tag"
        docker tag "$image_name`:temp" "$image_name`:$tag"
        docker push "$image_name`:$tag"

        "Try to publish rolling image: $image_name`:nanoserver-sac2016"
        docker tag "$image_name`:temp" "$image_name`:nanoserver-sac2016"
        docker push "$image_name`:nanoserver-sac2016"
    }
}
