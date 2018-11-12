FROM ubuntu:trusty

LABEL maintainer "Security Onion Solutions, LLC"
RUN apt-get update && apt-get -y upgrade
RUN apt-get -y install -f syslog-ng-core syslog-ng syslog-ng-mod-json netcat
RUN rm -rf /var/lib/apt/lists/*
RUN rm -rf /dev/log



ENTRYPOINT ["/usr/sbin/syslog-ng", "-F"]
