FROM centos:7

# Originally developed by Justin Henderson justin@hasecuritysolutions.com
LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="Domainstats HH1.0.7"
LABEL description="Domainstats running in Docker container for use with Security Onion"

RUN yum update -y && yum -y install epel-release
RUN yum -y install https://centos7.iuscommunity.org/ius-release-el7.rpm
RUN yum -y makecache && yum -y install python36u python36u-pip git && pip3.6 install --upgrade pip && yum clean all
RUN cd /opt && git clone https://github.com/MarkBaggett/domain_stats.git
RUN pip install python-whois six
RUN mkdir /var/log/domain_stats
RUN ln -sf /dev/stderr /var/log/domain_stats/domain_stats.log

RUN groupadd --gid 936 domainstats && \
    adduser --uid 936 --gid 936 \
      --home-dir /usr/share/domainstats --no-create-home \
      domainstats
RUN chown -R domainstats: /opt/domain_stats
USER domainstats

EXPOSE 20000

STOPSIGNAL SIGTERM

CMD /usr/bin/python3 /opt/domain_stats/domain_stats.py -ip 0.0.0.0 20000 -a /opt/domain_stats/top-1m.csv --preload 0
