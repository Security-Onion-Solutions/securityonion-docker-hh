FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="Cortex"
LABEL description="Cortex Docker container for use with Security Onion"
RUN yum update -y
RUN yum install -y https://dl.bintray.com/thehive-project/rpm-stable/cortex-3.0.0-1.noarch.rpm 
RUN yum -y install cortex wget
RUN groupmod -g 939 cortex \
  && usermod -u 939 -g 939 cortex \
  && ls -la /opt \
  && ls -la /opt/cortex
RUN mkdir -p /opt/cortex/conf
RUN chown -R cortex /opt/cortex \
     /var/log/cortex
     
USER cortex

ENTRYPOINT ["/opt/cortex/bin/cortex"]
