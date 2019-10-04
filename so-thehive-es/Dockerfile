# This Dockerfile was based on the official ElasticSearch Docker image:
# https://github.com/elastic/elasticsearch-docker

FROM centos:7
LABEL maintainer "Security Onion Solutions, LLC"

ENV PATH /usr/share/elasticsearch/bin:$PATH
ENV JAVA_HOME /usr/lib/jvm/jre-1.8.0-openjdk

RUN yum update -y && \
    yum install -y java-1.8.0-openjdk-headless wget which && \
    yum clean all

RUN groupadd -g 939 socore && adduser -u 939 -g 939 -d /usr/share/elasticsearch socore

WORKDIR /usr/share/elasticsearch

# Download/extract defined ES version. busybox tar can't strip leading dir.
RUN wget --progress=bar:force https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-oss-6.7.2.tar.gz && \
    EXPECTED_SHA=$(wget -O - https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-oss-6.7.2.tar.gz.sha512 | awk '{print $1}') && \
    test $EXPECTED_SHA == $(sha512sum elasticsearch-oss-6.7.2.tar.gz | awk '{print $1}') && \
    tar zxf elasticsearch-oss-6.7.2.tar.gz && \
    chown -R socore:socore elasticsearch-6.7.2 && \
    mv elasticsearch-6.7.2/* . && \
    rmdir elasticsearch-6.7.2 && \
    rm elasticsearch-oss-6.7.2.tar.gz


RUN set -ex && for esdirs in config data logs; do \
        mkdir -p "$esdirs"; \
        chown -R socore:socore "$esdirs"; \
    done

USER elasticsearch

# Install x-pack and also the ingest-{agent,geoip} modules required for Filebeat
#RUN for PLUGIN_TO_INST in ; do elasticsearch-plugin install --batch "$PLUGIN_TO_INST"; done
COPY elasticsearch.yml config/
COPY log4j2.properties config/
COPY bin/es-docker bin/es-docker

USER root
RUN chown socore:socore config/elasticsearch.yml config/log4j2.properties bin/es-docker && \
    chmod 0750 bin/es-docker

USER elasticsearch
CMD ["/bin/bash", "bin/es-docker"]

EXPOSE 9400 9500
