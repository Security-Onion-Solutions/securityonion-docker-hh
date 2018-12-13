FROM alpine
MAINTAINER Kolide Developers <engineering@kolide.co>

RUN apk --update add ca-certificates unzip curl
RUN mkdir -p /tmp/fleet && cd /tmp/fleet \
&& curl -O https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/Fleet1.0.5/sos_fleet_latest.zip \
&& unzip sos_fleet_latest.zip \
&& cp fleet/fleet /usr/bin/fleet \
&& cp fleet/fleetctl /usr/bin/fleetctl \
&& cd /tmp && rm -rf /tmp/fleet

COPY startfleet.sh /startfleet.sh
RUN chmod +x /startfleet.sh

ENTRYPOINT ["/startfleet.sh"]
