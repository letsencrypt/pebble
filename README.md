# Pebble

A miniature version of [Boulder](https://github.com/letsencrypt/boulder), Pebble
is a small [ACME-08](https://tools.ietf.org/html/draft-ietf-acme-acme-08) test
server not suited for use as a production CA.

## !!! WARNING !!!

![WARNING](https://media.giphy.com/media/IT6kBZ1k5oEeI/giphy.gif)

Pebble is **NOT INTENDED FOR PRODUCTION USE**. Pebble is for **testing only**.

By design Pebble will drop all of its state between invocations and will
randomize keys/certificates used for issuance.

## Goals

1. Produce a simplified testing front end
2. Move rapidly to gain [ACME draft-08](https://tools.ietf.org/html/draft-ietf-acme-acme-08) experience
3. Write "idealized" code that can be adopted back into Boulder
4. Aggressively build in guardrails against non-testing usage

Pebble aims to address the need for ACME clients to have an easier to use,
self-contained version of Boulder to test their clients against while developing
ACME-06 support. Boulder is multi-process, requires heavy dependencies (MariaDB,
RabbitMQ, etc), and is operationally complex to integrate with other projects.

Where possible Pebble aims to produce code that can be used to inform the
pending Boulder support for ACME-06, through contribution of code as well as
design lessons learned. Development of Pebble is meant to be rapid, and to
produce a minimum working prototype on a short schedule.

In places where the ACME specification allows customization/CA choice Pebble
aims to make choices different from Boulder. For instance, Pebble changes the
path structures for its resources and directory endpoints to differ from
Boulder. The goal is to emphasize client specification compatibility and to
avoid "over-fitting" on Boulder and the Let's Encrypt production service.

Lastly, Pebble will enforce it's test-only usage by aggressively building in
guardrails that make using it in a production setting impossible or very
inconvenient. Pebble will not support non-volatile storage or persistence
between executions. Pebble will also randomize keys/certificates used for
issuance. Where possible Pebble will make decisions that force clients to
implement ACME correctly (e.g. randomizing `/directory` endpoint URLs to ensure
clients are not hardcoding URLs.)

## Install

1. [Set up Go](https://golang.org/doc/install) and your `$GOPATH`
2. `go get -u github.com/letsencrypt/pebble/...`
3. `cd $GOPATH/src/github.com/letsencrypt/pebble && go install ./...`
4. `pebble -h`

## Usage

`pebble -config ./test/config/pebble-config.json`

### Testing at full speed

By default Pebble will sleep a random number of seconds (from 1 to 15) between
individual challenge validation attempts. This ensures clients don't make
assumptions about when the challenge is solved from the CA side by observing
a single request for a challenge response. Instead clients must poll the
challenge to observe the state since the CA may send many validation requests.

To test issuance "at full speed" with no artificial sleeps set the environment
variable `PEBBLE_VA_NOSLEEP` to `1`. E.g.

`PEBBLE_VA_NOSLEEP=1 pebble -config ./test/config/pebble-config.json`

### Avoiding Client HTTPS Errors

By default Pebble is accessible over HTTPS-only and uses a [test
certificate](test/certs/localhost/cert.pem) generated using a [test
CA](test/certs/pebble.minica.pem) (See [the`test/certs/`
directory](test/certs/README.md) for more information).

Since the Pebble test CA isn't part of any default CA trust stores you must add
the [`test/certs/pebble.minica.pem`](test/certs/pebble.minica.pem) certificate
to your client's trusted root configuration to avoid HTTPS errors. Your client
should offer a runtime option to specify a list of trusted root CAs.

**IMPORTANT: Do not add the `pebble.minica.pem` CA to the system-wide trust
store or to any production systems/codebases. The private key for this CA is
intentionally made [publically available in this
repo](test/certs/pebble.minica.key.pem).**
