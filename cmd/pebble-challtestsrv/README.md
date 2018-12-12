# Pebble Challenge Test Server

**Important note: The `pebble-challtestsrv` command is for TEST USAGE ONLY. It
is trivially insecure, offering no authentication. Only use
`pebble-challtestsrv` in a controlled test environment.**

The standalone `pebble-challtestsrv` binary lets you run HTTP-01, HTTPS HTTP-01,
DNS-01, and TLS-ALPN-01 challenge servers that external programs can add/remove
challenge responses to using a HTTP management API.

For example this is used by the Boulder integration tests to easily add/remove
TXT records for DNS-01 challenges for the `chisel.py` ACME client, and to test
redirect behaviour for HTTP-01 challenge validation.

### Usage

```
Usage of pebble-challtestsrv:
  -dns01 string
    Comma separated bind addresses/ports for DNS-01 challenges and fake DNS data. Set empty to disable. (default ":8053")
  -http01 string
    Comma separated bind addresses/ports for HTTP-01 challenges. Set empty to disable. (default ":5002")
  -https01 string
    Comma separated bind addresses/ports for HTTPS HTTP-01 challenges. Set empty to disable. (default ":5003")
  -management string
    Bind address/port for management HTTP interface (default ":8055")
  -tlsalpn01 string
    Comma separated bind addresses/ports for TLS-ALPN-01 and HTTPS HTTP-01 challenges. Set empty to disable. (default ":5001")
```

To disable a challenge type, set the bind address to `""`. E.g.:

* To run HTTP-01 only: `pebble-challtestsrv -dns01 "" -tlsalpn01 ""`
* To run DNS-01 only: `challtestsrv -http01 "" -tlsalpn01 ""`
* To run TLS-ALPN-01 only: `challtestsrv -http01 "" -dns01 ""`

### Management Interface

_Note: These examples assume the default `-management` interface address, `:8055`._

#### Mock DNS

##### Default A/AAAA Responses

To set the default IPv4 address used for responses to `A` queries that do not
match explicit mocks run:

    curl -X POST -d '{"ip":"10.10.10.2"}' http://localhost:8055/set-default-ipv4

Similarly to set the default IPv6 address used for responses to `AAAA` queries
that do not match explicit mocks run:

    curl -X POST -d '{"ip":"::1"}' http://localhost:8055/set-default-ipv6

To clear the default IPv4 or IPv6 address POST the same endpoints with an empty
(`""`) IP.

##### Mocked A/AAAA Responses

To add IPv4 addresses to be returned for `A` queries for
`test-host.letsencrypt.org` run:

    curl -X POST -d '{"host":"test-host.letsencrypt.org", "addresses":["12.12.12.12", "13.13.13.13"]}' http://localhost:8055/add-a

The mocked `A` responses can be removed by running:

    curl -X POST -d '{"host":"test-host.letsencrypt.org"}' http://localhost:8055/clear-a

To add IPv6 addresses to be returned for `AAAA` queries for
`test-host.letsencrypt.org` run:

    curl -X POST -d '{"host":"test-host.letsencrypt.org", "addresses":["2001:4860:4860::8888", "2001:4860:4860::8844"]}' http://localhost:8055/add-aaaa

The mocked `AAAA` responses can be removed by running:

    curl -X POST -d '{"host":"test-host.letsencrypt.org"}' http://localhost:8055/clear-aaaa

##### Mocked CAA Responses

To add a mocked CAA policy for `test-host.letsencrypt.org` that allows issuance
by `letsencrypt.org` run:

    curl -X POST -d '{"host":"test-host.letsencrypt.org", "policies":[{"tag":"issue","value":"letsencrypt.org"}]}' http://localhost:8055/add-caa

To remove the mocked CAA policy for `test-host.letsencrypt.org` run:

    curl -X POST -d '{"host":"test-host.letsencrypt.org"}' http://localhost:8055/clear-caa

#### HTTP-01

To add an HTTP-01 challenge response for the token `"aaaa"` with the content `"bbbb"` run:

    curl -X POST -d '{"token":"aaaa", "content":"bbbb"}' http://localhost:8055/add-http01

Afterwards the challenge response will be available over HTTP at
`http://localhost:5002/.well-known/acme-challenge/aaaa`, and HTTPS at
`https://localhost:5002/.well-known/acme-challenge/aaaa`.

The HTTP-01 challenge response for the `"aaaa"` token can be deleted by running:

    curl -X POST -d '{"token":"aaaa"}' http://localhost:8055/del-http01

##### Redirects

To add a redirect from `/.well-known/acme-challenge/whatever` to
`https://localhost:5003/ok` run:

    curl -X POST -d '{"path":"/.well-known/whatever", "targetURL": "https://localhost:5003/ok"}' http://localhost:8055/add-redirect

Afterwards HTTP requests to `http://localhost:5002/.well-known/whatever/` will
be redirected to `https://localhost:5003/ok`. HTTPS requests that match the
path will not be served a redirect to prevent loops when redirecting the same
path from HTTP to HTTPS.

To remove the redirect run:

    curl -X POST -d '{"path":"/.well-known/whatever"}' http://localhost:8055/del-redirect

#### DNS-01

To add a DNS-01 challenge response for `_acme-challenge.test-host.letsencrypt.org` with
the value `"foo"` run:

    curl -X POST -d '{"host":"_acme-challenge.test-host.letsencrypt.org", "value": "foo"}' http://localhost:8055/add-txt

To remove the mocked DNS-01 challenge response run:

    curl -X POST -d '{"host":"_acme-challenge.test-host.letsencrypt.org"}' http://localhost:8055/clear-txt

#### TLS-ALPN-01

To add a TLS-ALPN-01 challenge response certificate for the host
`test-host.letsencrypt.org` with the key authorization `"foo"` run:

    curl -X POST -d '{"host":"test-host.letsencrypt.org", "content":"foo"}' http://localhost:8055/add-tlsalpn01

To remove the mocked TLS-ALPN-01 challenge response run:

    curl -X POST -d '{"host":"test-host.letsencrypt.org"}' http://localhost:8055/clear-tlsalpn01

#### Request History

`pebble-challtestsrv` keeps track of the requests processed by each of the
challenge servers and exposes this information via JSON.

To get the history of HTTP requests run:

    curl http://localhost:8055/http-request-history

Each HTTP request event is an object of the form:
```
   {
      "Time": "2018-12-12T16:42:20.667521441-05:00",
      "URL": "/test-whatever/dude?token=blah",
      "Host": "localhost:5002",
      "Method": "GET",
      "Path": "/test-whatever/dude",
      "HTTPS": false
   }
```

To get the history of DNS requests run:

    curl http://localhost:8055/dns-request-history

Each DNS request event is an object of the form:
```
   {
      "Time": "2018-12-12T16:42:34.465299005-05:00",
      "Question": {
         "Name": "bogdog.cog.",
         "Qtype": 257,
         "Qclass": 1
      }
   }
```

To get the history of TLS-ALPN-01 requests run:

    curl http://localhost:8055/tlsalpn01-request-history

Each TLS-ALPN-01 request event is an object of the form:
```
   {
      "Time": "2018-12-12T16:42:50.654684756-05:00",
      "ServerName": "heydudez.watup",
      "SupportedProtos": [
         "dogzrule"
      ]
   }
```

To clear all request history run:

    curl -X POST -d '{}' http://localhost:8055/clear-request-history
