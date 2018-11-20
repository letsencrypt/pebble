# Challenge Test Server

The `challtestsrv` package offers a library/command that can be used by test
code to respond to HTTP-01, DNS-01, and TLS-ALPN-01 ACME challenges. The
`challtestsrv` package can also be used as a mock DNS server letting
external code add mock A, AAAA, and CAA DNS data for specific hostnames.

**Important note: The `challtestsrv` command and library are for TEST USAGE
ONLY. It is trivially insecure, offering no authentication. Only use
`challtestsrv` in a controlled test environment.**

## Standalone `pebble-challtestsrv` Command

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

_Note: These examples assume the default `-management` interface address, `:8056`._

#### Mock DNS

##### Default A/AAAA Responses

To set the default IPv4 address used for responses to `A` queries that do not
match explicit mocks run:

    curl -X POST -d '{"ip":"10.10.10.2"}' http://localhost:8056/set-default-ipv4

Similarly to set the default IPv6 address used for responses to `AAAA` queries
that do not match explicit mocks run:

    curl -X POST -d '{"ip":"::1"}' http://localhost:8056/set-default-ipv6

To clear the default IPv4 or IPv6 address POST the same endpoints with an empty
(`""`) IP.

##### Mocked A/AAAA Responses

To add IPv4 addresses to be returned for `A` queries for
`test-host.letsencrypt.org` run:

    curl -X POST -d '{"host":"test-host.letsencrypt.org", "addresses":["12.12.12.12", "13.13.13.13"]}' http://localhost:8056/add-a

The mocked `A` responses can be removed by running:

    curl -X POST -d '{"host":"test-host.letsencrypt.org"}' http://localhost:8056/clear-a

To add IPv6 addresses to be returned for `AAAA` queries for
`test-host.letsencrypt.org` run:

    curl -X POST -d '{"host":"test-host.letsencrypt.org", "addresses":["2001:4860:4860::8888", "2001:4860:4860::8844"]}' http://localhost:8056/add-aaaa

The mocked `AAAA` responses can be removed by running:

    curl -X POST -d '{"host":"test-host.letsencrypt.org"}' http://localhost:8056/clear-aaaa

##### Mocked CAA Responses

To add a mocked CAA policy for `test-host.letsencrypt.org` that allows issuance
by `letsencrypt.org` run:

    curl -X POST -d '{"host":"test-host.letsencrypt.org", "policies":[{"tag":"issue","value":"letsencrypt.org"}]}' http://localhost:8055/add-caa

To remove the mocked CAA policy for `test-host.letsencrypt.org` run:

    curl -X POST -d '{"host":"test-host.letsencrypt.org"}' http://localhost:8055/clear-caa

#### HTTP-01

To add an HTTP-01 challenge response for the token `"aaaa"` with the content `"bbbb"` run:

    curl -X POST -d '{"token":"aaaa", "content":"bbbb"}' http://localhost:8056/add-http01

Afterwards the challenge response will be available over HTTP at
`http://localhost:5002/.well-known/acme-challenge/aaaa`, and HTTPS at
`https://localhost:5002/.well-known/acme-challenge/aaaa`.

The HTTP-01 challenge response for the `"aaaa"` token can be deleted by running:

    curl -X POST -d '{"token":"aaaa"}' http://localhost:8056/del-http01

##### Redirects

To add a redirect from `/.well-known/acme-challenge/whatever` to
`https://localhost:5003/ok` run:

    curl -X POST -d '{"path":"/.well-known/whatever", "targetURL": "https://localhost:5003/ok"}' http://localhost:8056/add-redirect

Afterwards HTTP requests to `http://localhost:5002/.well-known/whatever/` will
be redirected to `https://localhost:5003/ok`. HTTPS requests that match the
path will not be served a redirect to prevent loops when redirecting the same
path from HTTP to HTTPS.

To remove the redirect run:

    curl -X POST -d '{"path":"/.well-known/whatever"}' http://localhost:8056/del-redirect

#### DNS-01

To add a DNS-01 challenge response for `_acme-challenge.test-host.letsencrypt.org` with
the value `"foo"` run:

    curl -X POST -d '{"host":"_acme-challenge.test-host.letsencrypt.org", "value": "foo"}' http://localhost:8056/add-txt

To remove the mocked DNS-01 challenge response run:

    curl -X POST -d '{"host":"_acme-challenge.test-host.letsencrypt.org"}' http://localhost:8056/clear-txt

#### TLS-ALPN-01

To add a TLS-ALPN-01 challenge response certificate for the host
`test-host.letsencrypt.org` with the key authorization `"foo"` run:

    curl -X POST -d '{"host":"test-host.letsencrypt.org", "content":"foo"}' http://localhost:8056/add-tlsalpn01

To remove the mocked TLS-ALPN-01 challenge response run:

    curl -X POST -d '{"host":"test-host.letsencrypt.org"}' http://localhost:8056/clear-tlsalpn01

## The `challtestsrv` package

The `challtestsrv` package can be used as a library by another program to avoid
needing to manage an external `challtestsrv` binary or use the HTTP based
management interface. For example this is used by the Boulder
[`load-generator`](https://github.com/letsencrypt/boulder/tree/9e39680e3f78c410e2d780a7badfe200a31698eb/test/load-generator)
command to manage its own in-process HTTP-01 challenge server.

### Usage

Create a challenge server responding to HTTP-01 challenges on ":8888" and
DNS-01 challenges on ":9999" and "10.0.0.1:9998":

```
  import "github.com/letsencrypt/pebble/challtestsrv"

  challSrv, err := challtestsrv.New(challsrv.Config{
    HTTPOneAddr: []string{":8888"},
    DNSOneAddr: []string{":9999", "10.0.0.1:9998"},
  })
  if err != nil {
    panic(err)
  }
```

Run the Challenge server and subservers:
```
  // Start the Challenge server in its own Go routine
  go challSrv.Run()
```

Add an HTTP-01 response for the token `"aaa"` and the value `"bbb"`, defer
cleaning it up again:
```
  challSrv.AddHTTPOneChallenge("aaa", "bbb")
  defer challSrv.DeleteHTTPOneChallenge("aaa")
```

Add a DNS-01 TXT response for the host `"_acme-challenge.example.com."` and the
value `"bbb"`, defer cleaning it up again:
```
  challSrv.AddDNSOneChallenge("_acme-challenge.example.com.", "bbb")
  defer challSrv.DeleteHTTPOneChallenge("_acme-challenge.example.com.")
```

Stop the Challenge server and subservers:
```
  // Shutdown the Challenge server
  challSrv.Shutdown()
```

For more information on the package API see Godocs and the associated package
sourcecode.
