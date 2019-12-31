#!/bin/bash

VERSION=6.8.6
DOCKERHUB="soshybridhunter"
TAG="HH1.1.4"

echo
echo "This script will build all Docker images for Security Onion."
echo
echo "It is currently set to build Elastic stack version ${VERSION}."
echo
echo "Press Enter to continue or Ctrl-c to cancel."
read PAUSE
echo

sed -i "s|X.Y.Z|$VERSION|g" so-elasticsearch/Dockerfile so-logstash/Dockerfile so-kibana/Dockerfile so-filebeat/Dockerfile so-thehive-es/Dockerfile

docker build -t $DOCKERHUB/so-elasticsearch:$TAG so-elasticsearch/ &&
docker build -t $DOCKERHUB/so-logstash:$TAG so-logstash/ && 
docker build -t $DOCKERHUB/so-kibana:$TAG so-kibana/ && 
docker build -t $DOCKERHUB/so-filebeat:$TAG so-filebeat/ &&
docker build -t $DOCKERHUB/so-thehive-es:$TAG so-thehive-es/
#docker build -t $DOCKERHUB/so-curator:$TAG so-curator/ && 
#docker build -t $DOCKERHUB/so-elastalert:$TAG so-elastalert/ 
#docker build -t $DOCKERHUB/so-domainstats:$TAG so-domainstats/ && 
#docker build -t $DOCKERHUB/so-freqserver:$TAG so-freqserver/


sed -i "s|$VERSION|X.Y.Z|g" so-elasticsearch/Dockerfile so-logstash/Dockerfile so-kibana/Dockerfile

echo
docker images
