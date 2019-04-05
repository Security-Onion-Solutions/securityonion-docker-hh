FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="Wazuh Manager HH1.0.7"
LABEL description="Wazuh Manager and API running in Docker container for use with Security Onion"
RUN yum update -y
RUN yum install -y https://dl.bintray.com/thehive-project/rpm-stable/thehive-project-release-1.1.0-2.noarch.rpm
RUN yum -y install thehive
RUN groupmod -g 939 thehive \
  && usermod -u 939 -g 939 thehive \
  && ls -la /opt \
  && ls -la /opt/thehive
RUN mkdir -p /opt/thehive/conf
RUN chown -R thehive /opt/thehive \
                      /var/log/thehive
RUN echo "play.http.secret.key=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 49)" >> /opt/thehive/conf/application.conf \
  && echo -e 'search.host = ["elasticsearch:9300"]\n\
play.http.secret.key = ${?PLAY_SECRET}' >> /opt/thehive/conf/application.conf

USER thehive

EXPOSE 9000

ENTRYPOINT ["/opt/thehive/bin/thehive"]
