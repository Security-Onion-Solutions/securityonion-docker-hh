FROM ubuntu:bionic-20180526

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="apt-cacher running in Docker container for use with Security Onion"

ENV APT_CACHER_NG_VERSION=3.1 \
    APT_CACHER_NG_CACHE_DIR=/var/cache/apt-cacher-ng \
    APT_CACHER_NG_LOG_DIR=/var/log/apt-cacher-ng \
    APT_CACHER_NG_USER=socore

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
      apt-cacher-ng=${APT_CACHER_NG_VERSION}* \
 && rm -rf /var/lib/apt/lists/*

 # Create socore user.
 RUN addgroup --gid 939 socore && \
     adduser --uid 939 --gid 939 \
     --home /opt/so --no-create-home socore

COPY files/so-entrypoint.sh /sbin/so-entrypoint.sh
COPY repos/* /etc/apt-cacher-ng/

RUN chmod 755 /sbin/so-entrypoint.sh && chown -R 939:939 /etc/apt-cacher-ng
RUN ln -sf /dev/stdout /var/log/apt-cacher-ng/apt-cacher.log; \
    ln -sf /dev/stderr /var/log/apt-cacher-ng/apt-cacher.err;

EXPOSE 3142/tcp

ENTRYPOINT ["/sbin/so-entrypoint.sh"]

CMD ["/usr/sbin/apt-cacher-ng"]
