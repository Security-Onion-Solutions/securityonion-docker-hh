FROM ubuntu:latest

WORKDIR /var/launcher
COPY launcher /var/launcher
COPY launcher/src/tools/* /usr/local/bin/  

#Install the packages we need
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcab \
    msitools \
    ruby \
    ruby-dev \ 
    rubygems \ 
    build-essential \
    cpio \
    binutils \
    cpio \
    cabextract \
    rpm && \
\
#Install fpm
gem install --no-ri --no-rdoc fpm && \
\
#Clean up what we can
apt-get -f -y --auto-remove remove build-essential autoconf libtool && \    
apt-get clean && \
rm -rf /var/lib/apt/lists/*

RUN chmod +x /var/launcher/generate-packages.sh 
ENTRYPOINT ["/var/launcher/generate-packages.sh"]