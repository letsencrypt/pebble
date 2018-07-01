FROM golang:1.10-alpine as builder

RUN apk --update upgrade \
&& apk --no-cache --no-progress add git mercurial bash gcc musl-dev curl tar \
&& rm -rf /var/cache/apk/*

WORKDIR /go/src/github.com/letsencrypt/pebble
COPY . .

RUN go get -u github.com/jmhodges/clock \
&& go get -u gopkg.in/square/go-jose.v2

RUN go install ./...

## main
FROM alpine:3.7

RUN apk update && apk add --no-cache --virtual ca-certificates

COPY --from=builder /go/bin/pebble /usr/bin/pebble
COPY --from=builder /go/src/github.com/letsencrypt/pebble/test/ /test/

ENTRYPOINT [ "/usr/bin/pebble" ]
