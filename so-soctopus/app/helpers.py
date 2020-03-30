#!/usr/bin/env python
# -*- coding: utf-8 -*-

from elasticsearch import Elasticsearch, RequestsHttpConnection
from config import parser, es_index
import certifi


esserver = parser.get('es', 'es_url')
es_user = parser.get('es', 'es_user', fallback="")
es_pass = parser.get('es', "es_pass", fallback="")
es_verifycert = parser.getboolean('es', 'es_verifycert', fallback=False)

if es_user and es_pass:
    if es_verifycert:
        es = Elasticsearch(esserver,
                           http_auth=(es_user, es_pass),
                           verify_certs=es_verifycert,
                           ca_certs=certifi.where(),
                           connection_class=RequestsHttpConnection)
    else:
        es = Elasticsearch(esserver,
                           http_auth=(es_user, es_pass),
                           connection_class=RequestsHttpConnection)

else:
    if es_verifycert:
        es = Elasticsearch(esserver,
                           verify_certs=es_verifycert,
                           ca_certs=certifi.where(),
                           connection_class=RequestsHttpConnection)
    else:
        es = Elasticsearch(esserver,
                           connection_class=RequestsHttpConnection)

# Core functions that are helpers
def getHits(esid):
    # Connect to Elastic and get information about the connection.
    search = es.search(index=f"*:{es_index}*", doc_type="doc",
                       body={"query": {"bool": {"must": {"match": {'_id': esid}}}}})
    hits = search['hits']['total']
    if hits > 0:
        return search


def getConn(conn_id):
    connsearch = es.search(index=f"*:{es_index}", doc_type="doc", body={
        "query": {"bool": {"must": [{"match": {"event_type": "bro_conn"}}, {"match": {"uid": conn_id}}]}}})
    # search = (index="*:logstash-bro*", doc_type="doc", body={"query": {"bool": {"must": [ {"terms": { "uid" : "test" }}, { "terms" :{ "event_type" : "bro_conn" } } ] } } } )
    hits = connsearch['hits']['total']
    if hits > 0:
        return connsearch


def doUpdate(esindex, esid, tags):
    # Connect to Elastic and get information about the connection.
    localindex = esindex.split(":")[1]
    # source_to_update = '{"doc"{ "tags":["blue"]}}'
    update = es.update(index=localindex, doc_type="_doc", id=esid, body={"doc": {"tags": tags}}, refresh=True)
    # update = es.update(index=esindex, doc_type="_doc", id=esid, body={"doc":{ "tags":["green"]}})
    return update
