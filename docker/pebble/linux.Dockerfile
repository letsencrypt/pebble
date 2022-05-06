FROM golang:1.18-alpine as builder

ENV CGO_ENABLED=0

WORKDIR /pebble-src
COPY . .

RUN go build -o /go/bin/pebble ./cmd/pebble

## main
FROM alpine:3.15.4

COPY --from=builder /go/bin/pebble /usr/bin/pebble
COPY --from=builder /pebble-src/test/ /test/

CMD [ "/usr/bin/pebble" ]

EXPOSE 14000
EXPOSE 15000
