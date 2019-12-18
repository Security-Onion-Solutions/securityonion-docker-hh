FROM golang AS build
LABEL maintainer "Security Onion Solutions, LLC"

COPY ./src/go/ /go/src/github.com/target/strelka/src/go/
RUN cd /go/src/github.com/target/strelka/src/go/cmd/strelka-filestream/ && \
    go get . && \
    CGO_ENABLED=0 go build -o /tmp/strelka-filestream .

FROM alpine
COPY --from=build /tmp/strelka-filestream /usr/local/bin/strelka-filestream
RUN addgroup -g 939 strelka && \
    adduser -u 939 -G strelka strelka --disabled-password \
    -h /etc/strelka --no-create-home strelka
RUN apk add --no-cache jq
USER strelka

