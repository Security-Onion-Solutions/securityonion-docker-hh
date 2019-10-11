#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, request
from destinations import createHiveAlert, createMISPEvent, createSlackAlert, createFIREvent, createGRRFlow, createRTIRIncident, createStrelkaScan,  playbookWebhook
from config import parser, filename
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisismysecret'

logging.basicConfig(filename=filename, level=logging.DEBUG)

@app.route("/fir/event/<esid>")
def sendFIR(esid):
    return createFIREvent(esid)

@app.route("/grr/flow/<esid>+<flow_name>")
def sendGRR(esid, flow_name):
    return createGRRFlow(esid, flow_name)

@app.route("/thehive/alert/<esid>")
def sendHiveAlert(esid):
    return createHiveAlert(esid)

@app.route("/misp/event/<esid>")
def sendMISP(esid):
    return createMISPEvent(esid)

@app.route("/rtir/incident/<esid>")
def sendRTIR(esid):
    return createRTIRIncident(esid)

@app.route("/slack/<esid>")
def sendSlack(esid):
    return createSlackAlert(esid)

@app.route("/strelka/filescan/<esid>")
def sendStrelka(esid):
    return createStrelkaScan(esid)

@app.route("/playbook/webhook", methods=['POST'])
def sendPlaybook():
    webhook_content = request.get_json()
    return playbookWebhook(webhook_content)

if __name__ == "__main__" :
    app.run(host='0.0.0.0', port=7000)
