FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="Community Bro 1.0.0"
LABEL description="Community Bro 1.0.0 running in a docker for use with Security Onion."

RUN yum update -y && \
    yum clean all

# Install epel
RUN yum -y install epel-release bash libpcap iproute && yum clean all
RUN yum -y install jemalloc numactl libnl3 libdnet gdb GeoIP luajit && \
    yum -y erase epel-release && yum clean all && rm -rf /var/cache/yum

# Install the Bro package
RUN rpm -i https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/CommunityBro_1.0.0.2/securityonion-communitybro-1.0.0.2.rpm

VOLUME ["/nsm/bro/logs", "/nsm/bro/spool", "/opt/bro/share/bro", "/opt/bro/etc/"]

# Create Bro User.
RUN groupadd --gid 937 bro && \
    adduser --uid 937 --gid 937 \
    --home-dir /opt/bro --no-create-home bro

# Fix those perms.. big worm
RUN chown -R 937:937 /opt/bro && \
    chown -R 937:937 /nsm/bro

# Copy over the entry script.
COPY files/bro.sh /usr/local/sbin/bro.sh
RUN chmod +x /usr/local/sbin/bro.sh

ENTRYPOINT ["/usr/local/sbin/bro.sh"]
