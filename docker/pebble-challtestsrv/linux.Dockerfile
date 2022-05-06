FROM golang:1.18-alpine as builder

ENV CGO_ENABLED=0

WORKDIR /pebble-src
COPY . .

RUN go build -o /go/bin/pebble-challtestsrv ./cmd/pebble-challtestsrv

## main
FROM alpine:3.15.4

COPY --from=builder /go/bin/pebble-challtestsrv /usr/bin/pebble-challtestsrv

CMD [ "/usr/bin/pebble-challtestsrv" ]
