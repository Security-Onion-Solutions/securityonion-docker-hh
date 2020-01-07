FROM centos:7

# Originally developed by Justin Henderson justin@hasecuritysolutions.com
LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="freqserver HH1.1.0"
LABEL description="freqserver running in Docker container for use with Security Onion"

RUN yum update -y && yum -y install epel-release
RUN yum -y install https://centos7.iuscommunity.org/ius-release-el7.rpm
RUN yum -y makecache && yum -y install python36u python36u-pip git && pip3.6 install --upgrade pip && yum clean all
RUN pip install python-whois six

RUN cd /opt && git clone https://github.com/MarkBaggett/freq.git

RUN mkdir /var/log/freq_server
RUN ln -sf /dev/stderr /var/log/freq_server/freq_server.log
RUN groupadd --gid 935 freqserver && \
    adduser --uid 935 --gid 935 \
      --home-dir /usr/share/freqserver --no-create-home \
      freqserver
RUN chown -R freqserver: /opt/freq
USER freqserver

EXPOSE 10004

STOPSIGNAL SIGTERM

CMD /usr/bin/python3 /opt/freq/freq_server.py -ip 0.0.0.0 10004 /opt/freq/freqtable2018.freq
