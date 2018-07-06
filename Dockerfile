FROM golang:1.10-alpine as builder

RUN apk --update upgrade \
&& apk --no-cache --no-progress add git bash curl \
&& rm -rf /var/cache/apk/*

WORKDIR /go/src/github.com/letsencrypt/pebble
COPY . .

RUN go get ./...

## main
FROM alpine:3.7

RUN apk update && apk add --no-cache --virtual ca-certificates

COPY --from=builder /go/bin/pebble /usr/bin/pebble
COPY --from=builder /go/src/github.com/letsencrypt/pebble/test/ /test/

CMD [ "/usr/bin/pebble" ]
