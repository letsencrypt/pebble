# Pebble

[![Build Status](https://travis-ci.org/letsencrypt/pebble.svg?branch=master)](https://travis-ci.org/letsencrypt/pebble)
[![Coverage Status](https://coveralls.io/repos/github/letsencrypt/pebble/badge.svg?branch=cpu-goveralls)](https://coveralls.io/github/letsencrypt/pebble?branch=cpu-goveralls)
[![Go Report Card](https://goreportcard.com/badge/github.com/letsencrypt/pebble)](https://goreportcard.com/report/github.com/letsencrypt/pebble)

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
support subproblems, or pre-authorization. Pebble does not support revoking a 
certificate issued by a different ACME account by proving authorization of all
of the certificate's domains.

Pebble does not perform all of the same input validation as Boulder. Some domain
names that would be rejected by Boulder/Let's Encrypt may work with Pebble.

Pebble does not enforce any rate limits. It is not presently an appropriate tool
for testing that your client handles Boulder/Let's Encrypt rate limits
correctly.

## Install

1. [Set up Go](https://golang.org/doc/install). Add ~/go/bin to your $PATH, or
   set GOBIN to a directory that is in your $PATH already.
2. git clone github.com/letsencrypt/pebble/
3. cd pebble
4. go install ./cmd/pebble

## Usage

### Binary

Assuming pebble is in your $PATH:

```bash
pebble -config ./test/config/pebble-config.json
```

Afterwards you can access the Pebble server's ACME directory
at `https://localhost:14000/dir`.

### Docker

Pebble includes a [docker-compose](https://docs.docker.com/compose/) file that
will create a `pebble` instance that uses a `pebble-challtestsrv` instance for
DNS resolution.

To download and start the containers run:

```
docker-compose up
```

Afterwards you can access the ACME API from your host machine at
`https://localhost:14000/dir`, `pebble`'s management interface
at `https://localhost:15000` and the `pebble-challtestsrv`'s management
interface at `http://localhost:8055`.

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
    - 14000:14000  # ACME port
    - 15000:15000  # Management port
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

### Default validation ports

To make it easier to test ACME clients and run challenge response servers
without root privileges Pebble defaults to validating ACME challenges using
unprivileged high ports:

* **Default HTTP-01 Port**: 5002
* **Default TLS-ALPN-01 Port**: 5001

These ports can be changed by editing the `"httpPort"` and `"tlsPort"` values of
the Pebble `-config` file provided to `pebble`.

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
gracefully handle these errors by default **Pebble rejects 5% of all valid
nonces as invalid**.

The percentage of valid nonces that are rejected can be configured using the
environment variable `PEBBLE_WFE_NONCEREJECT`. E.g. to reject 90% of good nonces
as invalid instead of 15% run:

`PEBBLE_WFE_NONCEREJECT=90 pebble`

To **never** reject a valid nonce as invalid run:

`PEBBLE_WFE_NONCEREJECT=0 pebble`

### Object Reuse

The RFC allows for several objects to be re-used.

**Clients should be prepared an ACME server may re-use any given object type, regardless of Pebble implementing a reuse policy for that object.**

Pebble and Boulder __may__ or __may not__ implement the same object re-use policies at any given time.  There exists an [ACME Implementation Details](https://github.com/letsencrypt/boulder/blob/main/docs/acme-implementation_details.md) document for Boulder which contains some information on how Boulder handles this.

#### Order Reuse

The RFC allows ACME servers to reuse an Order. Pebble does not reuse Orders at this time; however Boulder does reuse Orders in at least one scenario:

* If an Account requests a new Order that is identical to an already existing "pending" or "ready" Order for that same Account, the Order will be re-used.

#### Authorization Reuse

ACME servers may choose to reuse authorizations from previous orders in new orders. ACME clients [should always check](https://tools.ietf.org/html/rfc8555#section-7.1.3) the status of a new order and its authorizations to confirm whether they need to respond to any challenges.

#### Valid Authorization Reuse

**Pebble will reuse valid authorizations in new orders, if they exist, 50% of the time**.

The percentage may be controlled with the environment variable `PEBBLE_AUTHZREUSE`, e.g. to always reuse authorizations:

`PEBBLE_AUTHZREUSE=100 pebble`

#### Pending Authorization Reuse

Pebble does not currently reuse Pending Authorizations across Orders, however other ACME servers - notably Boulder - will reuse Pending Authorizations. 


### Avoiding Client HTTPS Errors

Pebble is accessible over HTTPS only and uses a [test
certificate](test/certs/localhost/cert.pem) generated using a [test
CA](test/certs/pebble.minica.pem) (See [the `test/certs/`
directory](test/certs/README.md) for more information).

Since the Pebble test CA isn't part of any default CA trust stores you must add
the [`test/certs/pebble.minica.pem`](test/certs/pebble.minica.pem) certificate
to your client's trusted root configuration to avoid HTTPS errors. Your client
should offer a runtime option to specify a list of trusted root CAs.

**IMPORTANT: Do not add the `pebble.minica.pem` CA to the system-wide trust
store or to any production systems/codebases. The private key for this CA is
intentionally made [publicly available in this
repo](test/certs/pebble.minica.key.pem).**

### Management interface

In order to ease the interaction of Pebble with testing systems, a specific HTTP
management interface is exposed on a different port than the ACME protocol,
and offers several useful testing endpoints.

These endpoints are specific to Pebble and its internal behavior, and are not part
of the RFC 8555 that defines the ACME protocol.

The management interface is configured by the `managementListenAddress` field in
`pebble-config.json` that defines the address and the port on which the management
interface will listen on. Set `managementListenAddress` to an empty string or `null`
to disable it.

The default configuration for this management interface as defined in
`test/config/pebble-config.json` is to listen on any address on port 15000:

```
  "managementListenAddress": "0.0.0.0:15000",
```

#### CA Root and Intermediate Certificates

Note that the CA's root and intermediate certificates are regenerated on every
launch. They can be retrieved by a `GET` request to `https://localhost:15000/roots/0`
and `https://localhost:15000/intermediates/0` respectively.

You might need the root certificate to verify the complete trust chain of
generated certificates, for example in end-to-end tests.

The private keys of these certificates can also be retrieved by a `GET` request
to `https://localhost:15000/root-keys/0` and `https://localhost:15000/intermediate-keys/0`
respectively.

**IMPORTANT: Do not add Pebble's root or intermediate certificate to a trust
store that you use for ordinary browsing or that is used for non-testing
purposes, since Pebble and its generated keys are not audited or held to the
same standards as the Let's Encrypt production CA and their keys. Moreover
these keys are exposed by Pebble and will be lost as soon as the process
terminates: so they are not safe to use for anything other than testing.**

In case alternative root chains are enabled by setting `PEBBLE_ALTERNATE_ROOTS` to a
positive integer, the root certificates for these can be retrieved by doing a `GET`
request to `https://localhost:15000/roots/0`, `https://localhost:15000/root-keys/1`
`https://localhost:15000/intermediates/2`, `https://localhost:15000/intermediate-keys/3`
etc. These endpoints also send `Link` HTTP headers for all alternative root and
intermediate certificates and keys.

The length of certificate chains can be controlled using `PEBBLE_CHAIN_LENGTH`, which has
a default and minimum value of `1` (leaf + 1 intermediate). For higher values, Pebble will
include extra intermediate certificates between the leaf and the root. Extra intermediate
certificates are *not* exposed via the management interface.

#### Certificate Status

The certificate (in PEM format) and its revocation status can be queried by sending
a `GET` request to `https://localhost:15000/cert-status-by-serial/<serial>`, where
`<serial>` is the hexadecimal representation of the certificate's serial number (no `0x` prefix).
It can be obtained via:

    openssl x509 -in cert.pem -noout -serial | cut -d= -f2

The endpoint returns the information as a JSON object:

    $ curl -ki https://127.0.0.1:15000/cert-status-by-serial/66317d2e02f5d3d6
    HTTP/2 200
    cache-control: public, max-age=0, no-cache
    content-type: application/json; charset=utf-8
    link: <https://127.0.0.1:15000/dir>;rel="index"
    content-length: 1740
    date: Fri, 12 Jul 2019 22:14:21 GMT

    {
       "Certificate": "-----BEGIN CERTIFICATE-----\nMIIEVz...tcw=\n-----END CERTIFICATE-----\n",
       "Reason": 4,
       "RevokedAt": "2019-07-13T00:13:20.418489956+02:00",
       "Serial": "66317d2e02f5d3d6",
       "Status": "Revoked"
    }


### OCSP Responder URL

Pebble does not support the OCSP protocol as a responder and so does not set
the OCSP Responder URL in the issued certificates. However, if you setup a
proper OCSP Responder run side by side with Pebble, you may want to set this URL.
This is possible by setting the field `ocspResponderURL` of the `pebble-config.json`
consummed by Pebble to a non empty string: in this case, this string will be use
in the appropriate field of all issued certificates.

For instance, to have Pebble issue certificates that instruct a client to check the URL `http://127.0.0.1:4002`
to retrieve the OCSP status of a certificate, run Pebble with a `pebble-config.json` that includes:

```
  "ocspResponderURL": "http://127.0.0.1:4002",
```

### Listing orders

Pebble has support for enumerating all orders for an ACME account object according to
[RFC 8555, Section 7.1.2](https://tools.ietf.org/html/rfc8555#section-7.1.2.1). By default, three
orders are returned per page, to make it easy to test pagination. This number can be modified by
setting the `PEBBLE_WFE_ORDERS_PER_PAGE` environment variable to a positive integer. For example,
to have 15 orders per page, run

`PEBBLE_WFE_ORDERS_PER_PAGE=15 pebble`
