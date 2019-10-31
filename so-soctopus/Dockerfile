 FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="SOCtopus v0.1 HH1.1.0"
LABEL description="API for automating SOC-related functions"

RUN yum update -y && yum -y install epel-release
RUN yum -y install https://centos7.iuscommunity.org/ius-release-el7.rpm
#RUN rpm --import /etc/pki/rpm-gpg/IUS-COMMUNITY-GPG-KEY
RUN yum -y makecache && yum -y install python36u python36u-pip && pip3.6 install --upgrade pip && yum clean all
RUN mkdir -p SOCtopus
RUN mkdir -p SOCtopus/templates
RUN mkdir -p SOCtopus/playbook
ADD ./requirements.txt SOCtopus/
ADD ./app/*.py SOCtopus/
ADD ./app/*.conf SOCtopus/
ADD ./app/playbook/* SOCtopus/playbook/
ADD ./templates/* SOCtopus/templates/
WORKDIR SOCtopus
RUN pip3.6 install -r requirements.txt
ENTRYPOINT ["python3.6", "SOCtopus.py"]

