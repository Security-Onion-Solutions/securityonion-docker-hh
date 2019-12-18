#!/usr/bin/env python
# -*- coding: utf-8 -*-

from elasticsearch import Elasticsearch
from config import parser

# Core functions that are helpers
def getHits(esid):
    # Connect to Elastic and get information about the connection.
    esserver = parser.get('es', 'es_url')
    es = Elasticsearch(esserver)
    search = es.search(index="*:logstash-*", doc_type="doc", body={"query": {"bool": {"must": { "match": { '_id' : esid }}}}})
    hits = search['hits']['total']
    if hits > 0:
        return search

def getConn(conn_id):
    esserver = parser.get('es', 'es_url')
    es = Elasticsearch(esserver)
    connsearch = es.search(index="*:logstash-*", doc_type="doc", body={"query": {"bool": {"must": [ {"match":{"event_type":"bro_conn"}},{"match":{"uid": conn_id }}]}}})
    #search = (index="*:logstash-bro*", doc_type="doc", body={"query": {"bool": {"must": [ {"terms": { "uid" : "test" }}, { "terms" :{ "event_type" : "bro_conn" } } ] } } } )
    hits = connsearch['hits']['total']
    if hits > 0:
        return connsearch

def doUpdate(esindex,esid,tags):
    # Connect to Elastic and get information about the connection.
    esserver = parser.get('es', 'es_url')
    es = Elasticsearch(esserver)
    localindex = esindex.split(":")[1]
    #source_to_update = '{"doc"{ "tags":["blue"]}}'
    update = es.update(index=localindex, doc_type="_doc", id=esid, body={"doc":{ "tags":tags}}, refresh=True)
    #update = es.update(index=esindex, doc_type="_doc", id=esid, body={"doc":{ "tags":["green"]}})
    return update

