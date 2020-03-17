#!/bin/bash

VERSION=7.6.1
DOCKERHUB="soshybridhunter"
TAGPRE=""
TAG="HH1.2.1"
FLAVOR="-oss"
OPTIONS="--no-cache"
SKIP=0
PUSH="no"

#########################################
# Options
#########################################
usage()
{
cat <<EOF

SO Docker Image Build Script
  Options:
  
# Build Elastic search w/ Features
Ex. ./0_build_images.sh -i elasticsearch -t HH1.1.4 -f -y

# Build All Elastic Images (oss)
Ex.  ./0_build_images.sh -i elastic -t HH1.1.4 -y

# Build All Images
Ex. ./0_build_images.sh -i all -t HH1.1.4 -y

# Build Image with different (than default) repo
Ex. ./0_build_images.sh -i elasticsearch -t HH1.1.4 -d mynewrepo -y

  -h         Help
  -i         Docker image
  -d         Dockerhub repo
  -t         Image Tag
  -f         Use Features
  -o         Specify additional options
  -p         Push and sign
  -y         Skip prompt 

EOF
}


while getopts "hfypd:i:t:" OPTION
do
    case $OPTION in
            
        h)
            usage
            exit 0
            ;;
        i)
            BUILD=$OPTARG
            ;;
        d)
            DOCKERHUB=$OPTARG
            ;;
        f)
            FLAVOR=""
            TAGPRE="features-"
            ;;
        o)
            OPTIONS=$OPTARG
            ;;
        p)
            PUSH="yes"
            ;;
        t)
            TAG=$OPTARG
            ;;
        y)
	    SKIP=1
	    ;;
    esac
done

if [ "$SKIP" = 0 ]; then
    echo
    echo "This script will build all Docker images for Security Onion."
    echo
    echo "It is currently set to build Elastic stack version ${VERSION}."
    echo
    echo "Press Enter to continue or Ctrl-c to cancel."
    read PAUSE
    echo
fi

if [ "$PUSH" = "yes" ]; then
    echo "Tell me your secret:"
    read -s $KEY
fi 

# Elastic
for i in elasticsearch logstash kibana filebeat ; do
   if [ "$BUILD" = $i ] || [ "$BUILD" = "elastic" ] || [ "$BUILD" = "all" ]; then
       cp so-$i/Dockerfile so-$i/Dockerfile.bak
       sed -i "s|FLAVOR|$i${FLAVOR}|g" so-$i/Dockerfile
       sed -i "s|X.Y.Z|$VERSION|g" so-$i/Dockerfile
       docker build $OPTIONS -t $DOCKERHUB/so-$i:$TAGRPRE$TAG so-$i
       mv so-$i/Dockerfile.bak so-$i/Dockerfile
       if [ "PUSH" = "yes" ];then
           echo "$KEY" | docker trust sign $DOCKERHUB/so-wazuh:$TAGPRE$TAG
           docker push $DOCKERHUB/so-wazuh:$TAGPRE$TAG
       fi
   fi
done

# TheHive
for i in thehive thehive-cortex thehive-es; do
    if [ "$BUILD" = $i ] || [ "$BUILD" = "allthehive" ] || [ "$BUILD" = "all" ]; then
        if [ $i = "thehive-es" ]; then
            cp so-$i/Dockerfile so-$i/Dockerfile.bak
            sed -i "s|FLAVOR|elasticsearch${FLAVOR}|g" so-$i/Dockerfile
            sed -i "s|X.Y.Z|$VERSION|g" so-$i/Dockerfile
            docker build $OPTIONS -t $DOCKERHUB/so-$i:$TAGPRE$TAG so-$i
            mv so-$i/Dockerfile.bak so-$i/Dockerfile
        else
            docker build $OPTIONS -t $DOCKERHUB/so-$i:$TAG so-$i/
        fi
        if [ "PUSH" = "yes" ];then
           echo "$KEY" | docker trust sign $DOCKERHUB/so-wazuh:$TAGPRE$TAG
           docker push $DOCKERHUB/so-wazuh:$TAGPRE$TAG
       fi
    fi
    
done

# Single builds
for i in core curator elastalert domainstats fleet fleet-launcher freqserver grafana idstools influxdb mysql tcpreplay navigator playbook redis steno soctopus suricata telegraf wazuh zeek; do
    if [ "$BUILD" = $i ] || [ "$BUILD" = "all" ]; then
        if [ $i = "core" ]; then
            ./so-core/get_cyberchef && docker build $OPTIONS -t $DOCKERHUB/so-core:$TAG so-core/
        else  
            docker build $OPTIONS -t $DOCKERHUB/so-$i:$TAG so-$i/
        fi
        if [ "PUSH" = "yes" ]; then
           echo "$KEY" | docker trust sign $DOCKERHUB/so-wazuh:$TAGPRE$TAG
           docker push $DOCKERHUB/so-wazuh:$TAGPRE$TAG
       fi
    fi
done
