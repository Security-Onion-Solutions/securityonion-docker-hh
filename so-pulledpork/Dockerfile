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
LABEL version="PulledPork v0.7.4"
LABEL description="PulledPork for downloading rules"

RUN yum update -y && yum -y install perl-Sys-Syslog perl-Crypt-SSLeay perl-libwww-perl perl-LWP-Protocol-https perl-Archive-Tar &&\
    yum clean all && rm -rf /var/cache/yum

RUN rpm -i https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/pulledpork_0.7.4/securityonion-pulledpork-0.7.4.0-securityonion.rpm
COPY files/so-pulledpork.sh /opt/pulledpork/

RUN chmod +x /opt/pulledpork/so-pulledpork.sh

# Create socore user.
RUN groupadd --gid 939 socore && \
    adduser --uid 939 --gid 939 \
    --home-dir /opt/so --no-create-home socore

ENTRYPOINT ["/opt/pulledpork/so-pulledpork.sh"]
