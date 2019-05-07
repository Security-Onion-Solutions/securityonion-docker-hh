#!/bin/bash

rm -f garbage_file
while ! wget -O garbage_file ${ELASTICSEARCH_HOST}:9500 2>/dev/null
do
	echo "Waiting for Elasticsearch..."
	rm -f garbage_file
	sleep 1
done
rm -f garbage_file
sleep 5

/opt/thehive/bin/thehive
