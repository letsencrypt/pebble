# Pebble

[![Build Status](https://travis-ci.org/letsencrypt/pebble.svg?branch=master)](https://travis-ci.org/letsencrypt/pebble)
[![Coverage Status](https://coveralls.io/repos/github/letsencrypt/pebble/badge.svg?branch=cpu-goveralls)](https://coveralls.io/github/letsencrypt/pebble?branch=cpu-goveralls)
[![Go Report Card](https://goreportcard.com/badge/github.com/letsencrypt/pebble)](https://goreportcard.com/report/github.com/letsencrypt/pebble)
[![GolangCI](https://golangci.com/badges/github.com/letsencrypt/pebble.svg)](https://golangci.com/r/github.com/letsencrypt/pebble)

A miniature version of [Boulder](https://github.com/letsencrypt/boulder), Pebble
is a small [ACME](https://github.com/ietf-wg-acme/acme) test server not suited
for use as a production CA.

## !!! WARNING !!!

![WARNING](https://media.giphy.com/media/IT6kBZ1k5oEeI/giphy.gif)

Pebble is **NOT INTENDED FOR PRODUCTION USE**. Pebble is for **testing only**.

By design Pebble will drop all of its state between invocations and will
randomize keys/certificates used for issuance.

## Goals

Pebble has several top level goals:

1. Provide a simplified ACME testing front end
1. Provide a test-bed for new and compatibility breaking ACME features
1. Encourage ACME client best-practices
1. Aggressively build in guardrails against non-testing usage

Pebble aims to address the need for ACME clients to have an easier to use,
self-contained version of Boulder to test their clients against while developing
ACME v2 support. Boulder is multi-process, requires heavy dependencies (MariaDB,
gRPC, etc), and is operationally complex to integrate with other projects.

Where possible Pebble aims to be a test-bed for new ACME protocol features that
can be used to inform later Boulder support. Pebble provides a way for Boulder
developers to test compatibility breaking changes more aggressively than is
appropriate for Boulder.

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

## Limitations

Pebble is missing some ACME features (PRs are welcome!). It does not presently
support the "orders" field of account objects, subproblems, pre-authorization or
external account binding. Pebble does not support revoking a certificate issued
by a different ACME account by proving authorization of all of the certificate's
domains.

Pebble does not perform all of the same input validation as Boulder. Some domain
names that would be rejected by Boulder/Let's Encrypt may work with Pebble.

Pebble does not enforce any rate limits. It is not presently an appropriate tool
for testing that your client handles Boulder/Let's Encrypt rate limits
correctly.

## Install

1. [Set up Go](https://golang.org/doc/install) and your `$GOPATH`
2. `go get -u github.com/letsencrypt/pebble/...`
3. `cd $GOPATH/src/github.com/letsencrypt/pebble && go install ./...`
4. `pebble -h`

## Usage

### Binary

```bash
pebble -config ./test/config/pebble-config.json
```

Afterwards you can access the Pebble server's ACME directory
at `https://localhost:14000/dir`.

### Docker

Pebble includes a [docker-compose](https://docs.docker.com/compose/) file that
will create a `pebble` instance that uses a `pebble-challtestsrv` instance for
DNS resolution.

To build and start the containers run:

```
docker-compose up
```

Afterwards you can access the ACME API from your host machine at
`https://localhost:14000/dir` and the `pebble-challtestsrv`'s management
interface at `http://locahost:8055`.

To get started you may want to update the `pebble-challtestsrv` mock DNS data
with a new default IPv4 address to use to respond to `A` queries from `pebble`:

```
curl --request POST --data '{"ip":"172.20.0.1"}' http://localhost:8055/set-default-ipv4
```

See the [pebble-challtestsrv
README](https://github.com/letsencrypt/pebble/blob/master/cmd/pebble-challtestsrv/README.md)
for more information.

#### Prebuilt Docker Images

If you would prefer not to use the provided `docker-compose.yml`, or to build
container images yourself, you can also use the [published
images](https://hub.docker.com/r/letsencrypt/pebble/).

With a docker-compose file:

```yaml
version: '3'

services:
 pebble:
  image: letsencrypt/pebble
  command: pebble -config /test/my-pebble-config.json
  ports:
    - 14000:14000
  environment:
    - PEBBLE_VA_NOSLEEP=1
  volumes:
    - ./my-pebble-config.json:/test/my-pebble-config.json
```

With a Docker command:

```bash
docker run -e "PEBBLE_VA_NOSLEEP=1" letsencrypt/pebble
# or
docker run -e "PEBBLE_VA_NOSLEEP=1" --mount src=$(pwd)/my-pebble-config.json,target=/test/my-pebble-config.json,type=bind letsencrypt/pebble pebble -config /test/my-pebble-config.json
```

**Note**: The Pebble dockerfile uses [multi-stage builds](https://docs.docker.com/develop/develop-images/multistage-build/) and requires Docker CE 17.05.0-ce or newer.

### Strict Mode

Pebble's goal to aggressively support new protocol features and backwards
compatibility breaking changes is slightly at odds with its goal to provide
a simple, light-weight ACME test server for clients to use in integration tests.
On the one hand we want to introduce breaking changes quickly and use Pebble as
a test-bed for this. On the other we want to make sure we don't break client
integration tests using Pebble too often.

As a balance to meet these two needs Pebble supports a `-strict` flag. By
running Pebble with `-strict false` changes known to break client compatibility
are disabled.

Presently we default `-strict` to false but this **will change in the future**.
If you are using Pebble for integration tests and favour reliability over
learning about breaking changes ASAP please explicitly run Pebble with `-strict
false`.

### DNS Server

By default Pebble uses the system DNS resolver, this may mean that caching causes
problems with DNS-01 validation. It may also mean that no DNSSEC validation is
performed.
You should configure your system's recursive DNS resolver according to your
needs or use the `-dnsserver` flag to define an address to a DNS server.

```
pebble -dnsserver 10.10.10.10:5053
pebble -dnsserver 8.8.8.8:53
pebble -dnsserver :5053
```

You may find it useful to set `pebble`'s `-dnsserver` to the address you used as
the `-dns01` argument when starting up a `pebble-challtestsrv` instance. This
will let you easily mock DNS data for Pebble. See the included
`docker-compose.yml` and the [pebble-challtestsrv
README](https://github.com/letsencrypt/pebble/blob/master/cmd/pebble-challtestsrv/README.md)
for more information.

### Testing at full speed

By default Pebble will sleep a random number of seconds (from 0 to 15) between
individual challenge validation attempts. This ensures clients don't make
assumptions about when the challenge is solved from the CA side by observing
a single request for a challenge response. Instead clients must poll the
challenge to observe the state since the CA may send many validation requests.

To test issuance "at full speed" with no artificial sleeps set the environment
variable `PEBBLE_VA_NOSLEEP` to `1`. E.g.

`PEBBLE_VA_NOSLEEP=1 pebble -config ./test/config/pebble-config.json`

The maximal number of seconds to sleep can be configured by defining
`PEBBLE_VA_SLEEPTIME`. It must be set to a positive integer.

### Skipping Validation

If you want to avoid the hassle of having to stand up a challenge response
server for real HTTP-01, DNS-01 or TLS-ALPN-01 validation requests Pebble
supports a mode that always treats challenge validation requests as successful.
By default this mode is disabled and challenge validation is performed.

To have all challenge POST requests succeed without performing any validation
run:

`PEBBLE_VA_ALWAYS_VALID=1 pebble`

### Invalid Anti-Replay Nonce Errors

The `urn:ietf:params:acme:error:badNonce` error type is meant to be retry-able.
When receiving this error a client should make a subsequent request to the
`/new-nonce` endpoint (or use the nonce from the error response) to retry the
failed request, rather than quitting outright.

Experience from Boulder indicates that many ACME clients do not gracefully retry
on invalid nonce errors. To help ensure future ACME clients are able to
gracefully handle these errors by default **Pebble rejects 15% of all valid
nonces as invalid**.

The percentage of valid nonces that are rejected can be configured using the
environment variable `PEBBLE_WFE_NONCEREJECT`. E.g. to reject 90% of good nonces
as invalid instead of 15% run:

`PEBBLE_WFE_NONCEREJECT=90 pebble`

To **never** reject a valid nonce as invalid run:

`PEBBLE_WFE_NONCEREJECT=0 pebble`

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
intentionally made [publicly available in this
repo](test/certs/pebble.minica.key.pem).**

### CA Root Certificate

Note that the CA's root certificate is regenerated on every launch. It can be
retrieved by a `GET` request to `https://localhost:14000/root`.

You might need the root certificate to verify the complete trust chain of
generated certificates, for example in end-to-end tests.

**IMPORTANT: Do not add Pebble's root or intermediate certificate to a trust
store that you use for ordinary browsing or that is used for non-testing
purposes, since Pebble and its generated keys are not audited or held to the
same standards as the Let's Encrypt production CA and their keys, and so are
not safe to use for anything other than testing. Also, their private keys
will be lost as soon as the Pebble process terminates.**
