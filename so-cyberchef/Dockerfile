FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="Cyberchef HH1.1.3"
LABEL description="Security Onion Cyberchef Docker Container"

RUN yum update -y && yum -y install epel-release && \
  curl -sL https://rpm.nodesource.com/setup_10.x | bash - && \
  yum clean all && yum makecache fast && \
  yum install -y git gcc-c++ make bzip2 && \
  yum install -y nodejs && \
  npm install -g grunt-cli && \
  git clone https://github.com/gchq/CyberChef && \
  cd CyberChef
WORKDIR /CyberChef
RUN npm install
RUN grunt prod
COPY ./entrypoint.sh .
RUN chmod +x entrypoint.sh
ENTRYPOINT ["/CyberChef/entrypoint.sh"]
