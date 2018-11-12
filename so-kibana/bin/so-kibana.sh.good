# Wait for ElasticSearch to come up, so that we can query for version infromation
echo -n "Waiting for ElasticSearch..."
COUNT=0
ELASTICSEARCH_CONNECTED="no"
while [[ "$COUNT" -le 240 ]]; do
  curl --output /dev/null --silent --head --fail http://"$ELASTICSEARCH_HOST":"$ELASTICSEARCH_PORT"
  if [ $? -eq 0 ]; then
    ELASTICSEARCH_CONNECTED="yes"
    echo "connected!"
    break
  else
    ((COUNT+=1))
    sleep 1
    echo -n "."
  fi
done
if [ "$ELASTICSEARCH_CONNECTED" == "no" ]; then
  echo
  echo -e "Connection attempt timed out.  Unable to connect to ElasticSearch.  \nPlease try: \n  -checking log(s) in /var/log/elasticsearch/\n  -running 'sudo docker ps' \n  -running 'sudo so-elastic-restart'"
  echo

  exit
fi

/usr/local/bin/kibana-docker &

# KIBANA_VERSION in /etc/nsm/securityonion.conf may not actually reflect the current Kibana version
	# Two possible cases:
	# 1. In the case of a new installation, KIBANA_VERSION is explicitly set to "UNKNOWN"
	# 2. In the case of a recent Kibana image upgrade, KIBANA_VERSION will be set to the previous version
	# Therefore, we need to get the current version from Elasticsearch
KIBANA_VERSION=$(curl -s http://$ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT | jq .version.number | sed 's/"//g')
SRC=/usr/share/
MAX_WAIT=240

# Check to see if Kibana is available
wait_step=0
  until curl -s -XGET http://localhost:5601 > /dev/null ; do
  wait_step=$(( ${wait_step} + 1 ))
  echo "Waiting on Kibana...Attempt #$wait_step"
	  if [ ${wait_step} -gt ${MAX_WAIT} ]; then
			  echo "ERROR: Kibana not available for more than ${MAX_WAIT} seconds."
			  exit 5
	  fi
		  sleep 1s;
  done

  # Apply Kibana config
  echo
  echo "Applying Kibana config..."
  curl -s -XPOST http://localhost:5601/api/saved_objects/config/$KIBANA_VERSION \
      -H "Content-Type: application/json" \
      -H "kbn-xsrf: $KIBANA_VERSION" \
      -d@/usr/share/kibana/config/config.json
  echo

  # Apply cross cluster search seed info for local Elasticsearch instance
  if [ ! -f /usr/share/kibana/config/ccseed.txt ]; then

    echo
    echo "Applying cross cluster search config..."
    curl -s -XPUT http://${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}/_cluster/settings \
         -H 'Content-Type: application/json' \
         -d "{\"persistent\": {\"search\": {\"remote\": {\"$MASTER\": {\"seeds\": [\"$ELASTICSEARCH_HOST:9300\"]}}}}}"
    echo
    touch /usr/share/kibana/config/ccseed.txt

  fi

  # Apply Kibana template
  echo
  echo "Applying Kibana template..."
  curl -s -XPUT http://${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}/_template/kibana \
       -H 'Content-Type: application/json' \
       -d'{"index_patterns" : ".kibana", "settings": { "number_of_shards" : 1, "number_of_replicas" : 0 }, "mappings" : { "search": {"properties": {"hits": {"type": "integer"}, "version": {"type": "integer"}}}}}'
  echo

  curl -s -XPUT "${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}/.kibana/_settings" \
       -H 'Content-Type: application/json' \
       -d'{"index" : {"number_of_replicas" : 0}}'
  echo


# Apply all the dashboards
# Load dashboards, visualizations, index pattern(s), etc.
for i in /usr/share/kibana/dashboards/*.json; do
	curl -XPOST localhost:5601/api/kibana/dashboards/import?force=true -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d @$i >> /var/log/kibana/dashboards.log 2>&1 &
	echo -n "."
done
# Add Custom dashboards
for i in /usr/share/kibana/custdashboards/*.json; do
	curl -XPOST localhost:5601/api/kibana/dashboards/import?force=true -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d @$i >> /var/log/kibana/dashboards.log 2>&1 &
	echo -n "."
done

sleep infinity
