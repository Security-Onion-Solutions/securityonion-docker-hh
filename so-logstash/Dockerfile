# This Dockerfile was based on the official Logstash Docker image:
# https://github.com/elastic/logstash-docker

# Copyright 2014,2015,2016,2017,2018 Security Onion Solutions, LLC

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"

# Install Java and the "which" command, which is needed by Logstash's shell
# scripts.
RUN yum update -y && \
    yum install -y java-1.8.0-openjdk-devel which && \
    yum clean all

# Provide a non-root user to run the process.
RUN groupadd --gid 931 logstash && \
    adduser --uid 931 --gid 931 \
      --home-dir /usr/share/logstash --no-create-home \
      logstash

# Add Logstash itself.
RUN curl -Lo - https://artifacts.elastic.co/downloads/logstash/logstash-oss-6.4.1.tar.gz | \
    tar zxf - -C /usr/share \
    && mv /usr/share/logstash-6.4.1 /usr/share/logstash \
    && chown --recursive logstash:logstash /usr/share/logstash/ \
    && ln -s /usr/share/logstash /opt/logstash && mkdir /usr/share/logstash/pipeline.so \
    && mkdir /usr/share/logstash/pipeline.freq && mkdir /usr/share/logstash/pipeline.dstats \
    && mkdir /usr/share/logstash/pipeline.enabled && chown --recursive 931:931 /usr/share/logstash/pipeline.enabled

ENV PATH=/usr/share/logstash/bin:$PATH

# Provide a minimal configuration, so that simple invocations will provide
# a good experience.
ADD config/logstash.yml config/log4j2.properties /usr/share/logstash/config/
ADD pipeline/default.conf /usr/share/logstash/pipeline/logstash.conf
ADD files/conf.d.so/* /usr/share/logstash/pipeline.so/
ADD files/dictionaries/ /lib/dictionaries/
ADD files/freq /usr/share/logstash/pipeline.freq/
ADD files/domainstats /usr/share/logstash/pipeline.dstats/

RUN chown --recursive logstash:logstash /usr/share/logstash/config/ /usr/share/logstash/pipeline/ /lib/dictionaries

# Ensure Logstash gets a UTF-8 locale by default.
ENV LANG='en_US.UTF-8' LC_ALL='en_US.UTF-8'

# Place the startup wrapper script.
ADD bin/docker-entrypoint /usr/local/bin/
RUN chmod 0755 /usr/local/bin/docker-entrypoint

USER logstash

# RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install x-pack
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-translate
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-tld
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-elasticsearch
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-rest

# ADD env2yaml/env2yaml /usr/local/bin/

EXPOSE 9600 5044

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
