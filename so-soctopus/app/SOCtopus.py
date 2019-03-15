#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask
from destinations import theHiveAlert
from config import parser, filename
import logging

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'thisismysecret'

logging.basicConfig(filename=filename, level=logging.DEBUG)


@app.route("/hive/alert/<esid>")
def sendHiveAlert(esid):
    return theHiveAlert(esid)

@app.route("/misp/event/<esid>")
def sendMISP(esid):
    return "MISP coming soon"

@app.route("/fir/incident/<esid>")
def sendFIR(esid):
    return "FIR coming soon"

@app.route("/rtir/incident/<esid>")
def sendRTIR(esid):
    return "RTIR coming soon"

@app.route("/grr/flow/<esid>")
def sendGRR(esid):
    return "GRR coming soon"

if __name__ == "__main__" :
    app.run(host='0.0.0.0', port=7000)#, ssl_context='adhoc')
