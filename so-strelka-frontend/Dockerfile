FROM golang AS build
LABEL maintainer "Security Onion Solutions, LLC"

COPY ./src/go/ /go/src/github.com/target/strelka/src/go/
RUN cd /go/src/github.com/target/strelka/src/go/cmd/strelka-frontend/ && \
    go get . && \
    CGO_ENABLED=0 go build -o /tmp/strelka-frontend .

FROM alpine
COPY --from=build /tmp/strelka-frontend /usr/local/bin/strelka-frontend
RUN addgroup -g 939 strelka && \
    adduser -u 939 -G strelka strelka --disabled-password \
    -h /etc/strelka --no-create-home strelka && \
    mkdir /var/log/strelka/ && \
    chown -R 939:939 /var/log/strelka/
USER strelka

