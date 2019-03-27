FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="SOCtopus v0.1 HH1.0.7"
LABEL description="API for automating SOC-related functions"

RUN yum update -y && yum -y install epel-release
RUN yum -y install https://centos7.iuscommunity.org/ius-release.rpm &&\
    rpm --import /etc/pki/rpm-gpg/IUS-COMMUNITY-GPG-KEY
RUN yum -y makecache && yum -y install python36u python36u-pip && pip3.6 install --upgrade pip && yum clean all
RUN mkdir -p SOCtopus
ADD ./requirements.txt SOCtopus/
ADD ./app/* SOCtopus/
WORKDIR SOCtopus
RUN pip3.6 install -r requirements.txt
ENTRYPOINT ["python3.6", "SOCtopus.py"]
