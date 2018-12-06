FROM alpine
MAINTAINER Kolide Developers <engineering@kolide.co>

RUN apk --update add ca-certificates unzip curl
RUN mkdir -p /tmp/fleet && cd /tmp/fleet \
&& curl -O https://dl.kolide.co/bin/fleet_latest.zip \
&& unzip fleet_latest.zip 'linux/*' -d fleet \
&& cp fleet/linux/fleet /usr/bin/fleet \
&& cp fleet/linux/fleetctl /usr/bin/fleetctl \
&& cd /tmp && rm -rf /tmp/fleet

COPY startfleet.sh /startfleet.sh
RUN chmod +x /startfleet.sh

ENTRYPOINT ["/startfleet.sh"]
