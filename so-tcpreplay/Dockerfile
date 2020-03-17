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
LABEL version "so-tcpreplay v0.1 HH1.2.1"
LABEL description="Replay PCAPs to sniffing interface(s)"

# Setup our utilities
RUN yum update -y && \
    yum clean all && \
    yum -y install epel-release && \
    yum -y install libpcap && \
    yum -y install tcpreplay && \
    yum -y install rpmrebuild && \
    yum -y install alien && \
    yum -y install wget

# Get PCAP DEBS
RUN for i in securityonion-samples_20121202-0ubuntu0securityonion4_all.deb securityonion-samples-bro_20170824-1ubuntu1securityonion3_all.deb securityonion-samples-markofu_20130522-0ubuntu0securityonion3_all.deb securityonion-samples-mta_20150103-0ubuntu0securityonion3_all.deb securityonion-samples-shellshock_20140926-0ubuntu0securityonion2_all.deb; do wget https://launchpad.net/~securityonion/+archive/ubuntu/stable/+files/$i; done

# Convert DEBs to RPMs
RUN alien -r *.deb

# Prep and install RPMs
RUN for i in securityonion-samples-20121202-1.noarch.rpm securityonion-samples-bro-20170824-2.noarch.rpm securityonion-samples-markofu-20130522-1.noarch.rpm securityonion-samples-mta-20150103-1.noarch.rpm securityonion-samples-shellshock-20140926-1.noarch.rpm  ; do rpmrebuild -p --change-spec-files='sed -e "s/%dir.*\"\/\"/#/"' -d/tmp/ $i && rpm -ivh /tmp/noarch/$i; done

# Clean up
RUN rm *.deb && \
    rm *.rpm

ENTRYPOINT ["/bin/bash"]

