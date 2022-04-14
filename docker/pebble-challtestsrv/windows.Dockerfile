FROM golang:1.18-nanoserver-sac2016 as builder

ENV CGO_ENABLED=0

WORKDIR /pebble-src
COPY . .

RUN go install -v ./cmd/pebble-challtestsrv/...

## main
FROM mcr.microsoft.com/windows/nanoserver:sac2016

COPY --from=builder /gopath/bin/pebble-challtestsrv.exe /gopath/bin/pebble-challtestsrv.exe

RUN powershell.exe -Command $path = $env:path + ';c:\gopath\bin'; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\' -Name Path -Value $path

CMD [ "/pebble-challtestsrv" ]
