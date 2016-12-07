# Pebble

A miniature version of [Boulder](https://github.com/letsencrypt/boulder), Pebble
is a small [ACME-04](https://tools.ietf.org/html/draft-ietf-acme-acme-04) test
server not suited for use as a production CA.

## !!! WARNING !!!

![WARNING](https://media.giphy.com/media/IT6kBZ1k5oEeI/giphy.gif)

Pebble is **NOT INTENDED FOR PRODUCTION USE**. Pebble is for **testing only**.

By design Pebble will drop all of its state between invocations and will
randomize keys/certificates used for issuance.

## Goals

1. Produce a simplified testing front end
2. Move rapidly to gain [ACME draft-04](https://tools.ietf.org/html/draft-ietf-acme-acme-04) experience
3. Write "idealized" code that can be adopted back into Boulder
4. Aggressively build in guardrails against non-testing usage

Pebble aims to address the need for ACME clients to have an easier to use,
self-contained version of Boulder to test their clients against while developing
ACME-04 support. Boulder is multi-process, requires heavy dependencies (MariaDB,
RabbitMQ, etc), and is operationally complex to integrate with other projects.

Where possible Pebble aims to produce code that can be used to inform the
pending Boulder support for ACME-04, through contribution of code as well as
design lessons learned. Development of Pebble is meant to be rapid, and to
produce a minimum working prototype on a short schedule.

Lastly, Pebble will enforce it's test-only usage by aggressively building in
guardrails that make using it in a production setting impossible or very
inconvenient. Pebble will not support non-volatile storage or persistence
between executions. Pebble will also randomize keys/certificates used for
issuance. Where possible Pebble will make decisions that force clients to
implement ACME correctly (e.g. randomizing `/directory` endpoint URLs to ensure
clients are not hardcoding URLs.)

## Install

1. [Set up Go](https://golang.org/doc/install) and your `$GOPATH`
2. `go get -u github.com/letsencrypt/pebble`
3. `go test ./... && go install ./...`
4. `pebble -h`

## Usage

`pebble -config ./test/config/pebble-config.json`
