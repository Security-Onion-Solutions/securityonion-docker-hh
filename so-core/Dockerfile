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
LABEL version="SO Core 0.0.2"
LABEL description="Security Onion Core Functions"

RUN yum update -y && yum -y install rsync epel-release &&\
    yum -y install nginx && \
    yum -y erase epel-release && yum clean all && rm -rf /var/cache/yum

RUN mkdir -p /opt/socore/bin
RUN mkdir -p /opt/socore/html

#COPY bin/* /opt/socore/bin/

#COPY files/startso.sh /opt/socore/
COPY files/html/* /opt/socore/html/

RUN chmod +x /opt/socore/startso.sh
RUN chmod +x /opt/socore/bin/*

# Create socore user.
RUN groupadd --gid 939 socore && \
    adduser --uid 939 --gid 939 \
    --home-dir /opt/so --no-create-home socore
RUN setcap cap_net_bind_service=ep /usr/sbin/nginx

EXPOSE 80
EXPOSE 443

ENTRYPOINT ["/opt/socore/startso.sh"]
