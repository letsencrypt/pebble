# Pebble
A miniature version of Boulder, Pebble is a small ACME test server not suited for a production CA

## Install

1. Set up Go and your `$GOPATH`
2. `go get -u github.com/letsencrypt/pebble`
3. `go test ./... && go install ./...`
4. `pebble -h`

## Usage

`pebble -config ./test/config/pebble-config.json`
