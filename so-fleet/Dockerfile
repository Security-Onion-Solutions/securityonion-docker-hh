FROM alpine
LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="Fleet 1.0.6 HH1.0.7"
LABEL description="Fleet running in Docker container for use with Security Onion"

RUN apk --update add ca-certificates unzip curl
RUN mkdir -p /tmp/fleet && cd /tmp/fleet \
&& curl -OL https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/Fleet1.0.6/sos_fleet_106.zip \
&& unzip sos_fleet_106.zip \
&& cp fleet /usr/bin/fleet \
&& cp fleetctl /usr/bin/fleetctl \
&& cd /tmp && rm -rf /tmp/fleet

COPY startfleet.sh /startfleet.sh
RUN chmod +x /startfleet.sh

ENTRYPOINT ["/startfleet.sh"]
