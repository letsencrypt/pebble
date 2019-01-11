FROM alpine:3.8

RUN apk update && apk add --no-cache --virtual ca-certificates

COPY pebble /usr/bin/pebble
COPY /test/ /test/

CMD [ "/usr/bin/pebble" ]