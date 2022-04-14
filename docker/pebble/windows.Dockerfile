FROM golang:1.18-nanoserver-sac2016 as builder

ENV CGO_ENABLED=0

WORKDIR /pebble-src
COPY . .

RUN go install -v ./cmd/pebble/...

## main
FROM mcr.microsoft.com/windows/nanoserver:sac2016

COPY --from=builder /gopath/bin/pebble.exe /gopath/bin/pebble.exe
COPY --from=builder /pebble-src/test/ /test/

RUN powershell.exe -Command $path = $env:path + ';c:\gopath\bin'; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\' -Name Path -Value $path

CMD [ "/pebble" ]

EXPOSE 14000
EXPOSE 15000
