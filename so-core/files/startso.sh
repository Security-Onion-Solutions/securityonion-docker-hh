#!/bin/bash

echo
#echo "Syncing base files with the host OS"
#rsync --update -raz /opt/socore/ /opt/so

echo
echo "Running Security Onion"

#for module in $(cat /opt/so/conf/enabledmodules.conf);
#  do
#    /opt/so/bin/so-$module-start
#done
nginx
sleep infinity
