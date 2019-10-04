FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="Sensoroni vsomething"
LABEL description="Sensoroni"

RUN yum update -y && \
    yum clean all

# Install libpcap
RUN yum -y install bash libpcap && yum clean all
RUN yum clean all && rm -rf /var/cache/yum

# Copy over the entry script.
COPY files/so-sensoroni.sh /usr/local/sbin/so-sensoroni.sh
RUN chmod +x /usr/local/sbin/so-sensoroni.sh

ENTRYPOINT ["/usr/local/sbin/so-sensoroni.sh"]
