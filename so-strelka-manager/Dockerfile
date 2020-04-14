FROM golang AS build
LABEL maintainer "Security Onion Solutions, LLC"

COPY ./src/go/ /go/src/github.com/target/strelka/src/go/
RUN cd /go/src/github.com/target/strelka/src/go/cmd/strelka-manager/ && \
    go get . && \
    CGO_ENABLED=0 go build -o /tmp/strelka-manager .

FROM alpine
COPY --from=build /tmp/strelka-manager /usr/local/bin/strelka-manager
RUN addgroup -g 939 strelka && \
    adduser -u 939 -G strelka strelka --disabled-password \
    -h /etc/strelka --no-create-home strelka
USER strelka
