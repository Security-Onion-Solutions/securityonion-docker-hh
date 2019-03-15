#!/usr/bin/env python
# -*- coding: utf-8 -*-
from helpers import getHits
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper
from flask import Flask,redirect
import uuid
import sys
import json
from config import parser
# This is where desitnation helper functions will go

def theHiveAlert(esid):
    search = getHits(esid)
    #Hive Stuff
    hive_url = parser.get('hive', 'hive_url')
    hive_key = parser.get('hive', 'hive_key')
    api = TheHiveApi(hive_url, hive_key)
    #if hits > 0:
    for result in search['hits']['hits']:

          # Check for src/dst IP/ports
          message = result['_source']['message']
          description = str(message)
          sourceRef = str(uuid.uuid4())[0:6]
          tags=["SecurityOnion"]
          artifacts=[]
          id = None

          if 'source_ip' in result['_source']:
              src = result['_source']['source_ip']
          if 'destination_ip' in result['_source']:
              dst = result['_source']['destination_ip']
          if 'source_port' in result['_source']:
              srcport = result['_source']['source_port']
          if 'destination_port' in result['_source']:
              dstport = result['_source']['destination_port']
          # NIDS Alerts
          if 'snort' in result['_source']['event_type']:
              alert = result['_source']['alert']
              category = result['_source']['category']
              sensor = result['_source']['interface']
              tags.append("nids")
              tags.append(category)
              title=alert
              # Add artifacts
              artifacts.append(AlertArtifact(dataType='ip', data=src))
              artifacts.append(AlertArtifact(dataType='ip', data=dst))
              artifacts.append(AlertArtifact(dataType='other', data=sensor))
              
          # Bro logs
          elif 'bro' in result['_source']['event_type']:
              _map_key_type ={
                  "conn": "Connection",
                  "dhcp": "DHCP",
                  "dnp3": "DNP3",
                  "dns": "DNS",
                  "files": "Files",
                  "ftp": "FTP",
                  "http": "HTTP",
                  "intel": "Intel",
                  "irc": "IRC",
                  "kerberos": "Kerberos",
                  "modbus": "Modbus",
                  "mysql": "MySQL",
                  "ntlm": "NTLM",
                  "pe": "PE",
                  "radius": "RADIUS",
                  "rdp": "RDP",
                  "rfb": "RFB",
                  "sip" : "SIP",
                  "smb": "SMB",
                  "smtp": "SMTP",
                  "snmp": "SNMP",
                  "ssh": "SSH",
                  "ssl": "SSL",
                  "syslog": "Syslog",
                  "weird": "Weird",
                  "x509": "X509"
              }

              def map_key_type(indicator_type):
                  '''
                  Maps a key type to use in the request URL.
                  '''

                  return _map_key_type.get(indicator_type)
              event_type = result['_source']['event_type']
              bro_tag = event_type.strip('bro_')
              bro_tag_title = map_key_type(bro_tag)
              print(bro_tag)
              uid = result['_source']['uid']
              if 'sensor_name' in result['_source']:
                  sensor = result['_source']['sensor_name']
                  artifacts.append(AlertArtifact(dataType='ip', data=src))
                  artifacts.append(AlertArtifact(dataType='ip', data=dst))
                  artifacts.append(AlertArtifact(dataType='other', data=uid))
                  artifacts.append(AlertArtifact(dataType='other', data=sensor))
              
              else:
                  artifacts.append(AlertArtifact(dataType='ip', data=src))
                  artifacts.append(AlertArtifact(dataType='ip', data=dst))
                  artifacts.append(AlertArtifact(dataType='other', data=uid))
              
              title= str('New Bro ' + bro_tag_title + ' record! - ' + uid)
              tags.append('bro')
              tags.append(bro_tag)

          # Wazuh/OSSEC logs
          elif 'ossec' in result['_source']['event_type']:
              agent_name = result['_source']['agent']['name']
              if 'description' in result['_source']:
                  ossec_desc = result['_source']['description']
              else:
                  ossec_desc = result['_source']['full_log']
              event_id = result['_source']['event_id']
              if 'ip' in result['_source']['agent']:
                  agent_ip = result['_source']['agent']['ip']
                  artifacts.append(AlertArtifact(dataType='ip', data=agent_ip))
                  artifacts.append(AlertArtifact(dataType='other', data=agent_name))
              else:
                  artifacts.append(AlertArtifact(dataType='other', data=agent_name))
              
              title= ossec_desc
              tags.append("wazuh")
          
          elif 'sysmon' in result['_source']['event_type']:
              if 'ossec' in result['_source']['tags']:
                  agent_name = result['_source']['agent']['name']
                  agent_ip = result['_source']['agent']['ip']
                  ossec_desc = result['_source']['full_log']
                  artifacts.append(AlertArtifact(dataType='ip', data=agent_ip))
                  artifacts.append(AlertArtifact(dataType='other', data=agent_name))
                 
              title= "New Sysmon Event! - " + agent_name
              tags.append("wazuh")
           
          else:
              title="New " + result['_source']['event_type'] + " Event From Security Onion" ,
          
          # Build alert
          hivealert = Alert(
              title= title,
              tlp=3,
              tags=tags,
              description=description,
              type='external',
              source='SecurityOnion',
              sourceRef=sourceRef,
              artifacts=artifacts
          )

          # Send it off
          response = api.create_alert(hivealert) 

          if response.status_code == 201:
              print(json.dumps(response.json(), indent=4, sort_keys=True))
              print('')
              id = response.json()['id']
          else:
              print('ko: {}/{}'.format(response.status_code, response.text))
              sys.exit(0)
    return redirect(hive_url + '/index.html#/alert/list')
