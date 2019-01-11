FROM alpine:3.8

RUN apk update && apk add --no-cache --virtual ca-certificates

COPY pebble-challtestsrv /usr/bin/pebble-challtestsrv

CMD [ "/usr/bin/pebble-challtestsrv" ]