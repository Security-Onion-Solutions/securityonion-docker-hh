FROM golang AS build
LABEL maintainer "Security Onion Solutions, LLC"

COPY ./go /go/src/github.com/target/strelka/src/go/
RUN cd /go/src/github.com/target/strelka/src/go/cmd/strelka-frontend/ && \
    go get . && \
    CGO_ENABLED=0 go build -o /tmp/strelka-frontend .

FROM alpine
COPY --from=build /tmp/strelka-frontend /usr/local/bin/strelka-frontend
RUN groupadd --gid 939 strelka && \
    adduser --uid 939 --gid 939 \
    --home-dir /etc/strelka --no-create-home strelka

RUN mkdir /var/log/strelka/ && \
    chown -R 939:939 /var/log/strelka/
USER strelka

