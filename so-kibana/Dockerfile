# This Dockerfile was based on the official Kibana Docker image:
# https://github.com/elastic/kibana-docker

FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"

EXPOSE 5601

# Add Reporting dependencies.
RUN yum update -y && \
    yum install -y fontconfig freetype epel-release && \
    yum install -y jq && yum -y erase epel-release && yum clean all && \
    rm -rf /var/cache/yum

WORKDIR /usr/share/kibana
RUN curl -Ls https://artifacts.elastic.co/downloads/kibana/kibana-oss-6.4.1-linux-x86_64.tar.gz | tar --strip-components=1 -zxf - && \
    ln -s /usr/share/kibana /opt/kibana

ENV PATH=/usr/share/kibana/bin:$PATH

# Copy over the dashboards
RUN mkdir /usr/share/kibana/dashboards
ADD dashboards/* /usr/share/kibana/dashboards/

# Add a self-signed SSL certificate for use in examples.
ADD ssl/kibana.example.org.* /usr/share/kibana/config/

# Provide a non-root user to run the process.
RUN groupadd --gid 932 kibana && \
    useradd --uid 932 --gid 932 \
      --home-dir /usr/share/kibana --no-create-home \
      kibana

# Add the launcher/wrapper script. It knows how to interpret environment
# variables and translate them to Kibana CLI options.
ADD bin/kibana-docker /usr/local/bin/

# Add our custom Security Onion Entry Script
ADD bin/so-kibana.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/so-kibana.sh

# Files are owned by 1000:1000 by default.
# This causes Kibana to fail on startup.
# Set ownership to kibana:kibana.
RUN chown --recursive kibana:kibana /usr/share/kibana/*
## Switch to limited user and run process.
USER kibana
#CMD /usr/local/bin/kibana-docker

ENTRYPOINT ["/usr/local/bin/so-kibana.sh"]
#ENTRYPOINT ["/bin/bash"]
