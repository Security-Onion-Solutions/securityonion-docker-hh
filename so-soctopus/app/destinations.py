#!/usr/bin/env python
# -*- coding: utf-8 -*-
from helpers import getHits
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper
from pymisp import PyMISP
from grr_api_client import api
from flask import redirect
from config import parser
import json
import uuid
import sys
import rt
import requests

def createHiveAlert(esid):
    search = getHits(esid)
    #Hive Stuff
    hive_url = parser.get('hive', 'hive_url')
    hive_key = parser.get('hive', 'hive_key')
    hive_verifycert = parser.get('hive', 'hive_verifycert')
    tlp = int(parser.get('hive', 'hive_tlp'))
    api = TheHiveApi(hive_url, hive_key, cert=hive_verifycert)
    #if hits > 0:
    for result in search['hits']['hits']:

          # Check for sdescription = str(message)description = str(message)rc/dst IP/ports
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
              title = "New " + result['_source']['event_type'] + " Event From Security Onion"
          
          # Build alert
          hivealert = Alert(
              title= title,
              tlp=tlp,
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
    
    # Redirect to TheHive instance
    return redirect(hive_url + '/index.html#/alert/list')

def createMISPEvent(esid):
    search = getHits(esid)
    #MISP Stuff
    misp_url = parser.get('misp', 'misp_url')
    misp_key = parser.get('misp', 'misp_key')
    misp_verifycert = parser.get('misp', 'misp_verifycert')
    distrib= parser.get('misp', 'distrib')
    threat = parser.get('misp', 'threat')
    analysis = parser.get('misp', 'analysis')
    
    for result in search['hits']['hits']:
        result = result['_source']
        message = result['message']
        description = str(message)
        info = description
        
        def init(url, key):
            return PyMISP(url, key, misp_verifycert, 'json', debug=True)
         
        misp = init(misp_url, misp_key)

        event = misp.new_event(distrib, threat, analysis, info)
        event_id = str(event['Event']['id'])

        if 'source_ip' in result:
            data_type = "ip-src"
            source_ip = result['source_ip']
            misp.add_named_attribute(event_id, data_type, source_ip )

        if 'destination_ip' in result:
            data_type = "ip-dst"
            destination_ip = result['destination_ip']
            misp.add_named_attribute(event_id, data_type, destination_ip )
            
    # Redirect to MISP instance    
    return redirect(misp_url + '/events/index')

def createGRRFlow(esid, flow_name):
    search = getHits(esid)
    grr_url = parser.get('grr', 'grr_url')
    grr_user = parser.get('grr', 'grr_user')
    grr_pass = parser.get('grr', 'grr_pass')
    grrapi = api.InitHttp(api_endpoint=grr_url,
                      auth=(grr_user, grr_pass))
  
    for result in search['hits']['hits']:
        result = result['_source']
        message = result['message']
        description = str(message)
        info = description
        
        if 'source_ip' in result:
            source_ip = result['source_ip']
       
        if 'destination_ip' in result:
            destination_ip = result['destination_ip']
        
        for ip in source_ip, destination_ip:
            search_result = grrapi.SearchClients(ip)
            grr_result = {}
            client_id = ''
            for client in search_result:
                # Get client id
                client_id = client.client_id
                client_last_seen_at = client.data.last_seen_at
                grr_result[client_id] = client_last_seen_at
                #flow_name = "ListProcesses"
                if client_id is None:
                    pass
                
                # Run flow
                flow_obj = grrapi.Client(client_id)
                flow_obj.CreateFlow(name=flow_name)
	
        if client_id != '':
            # Redirect to GRR instance
            return redirect(grr_url + '/#/clients/' + client_id + '/flows')    
        else:
            return "No matches found for source or destination ip"

def createRTIRIncident(esid):
    search = getHits(esid)
    for result in search['hits']['hits']:
        result = result['_source']
        message = result['message']
        description = str(message)
        event_type = result['event_type']
        rtir_url = parser.get('rtir', 'rtir_url')
        rtir_uri = parser.get('rtir', 'rtir_api')
        rtir_user = parser.get('rtir', 'rtir_user')
        rtir_pass = parser.get('rtir', 'rtir_pass')
        rtir_queue = parser.get('rtir', 'rtir_queue')
        rtir_creator = parser.get('rtir', 'rtir_creator')
        rtir_subject = 'New ' + event_type + ' event from Security Onion!'
        rtir_text = description
        rtir_rt = rt.Rt(rtir_url + '/' + rtir_api, rtir_user, rtir_pass, verify_cert=False)
        rtir_rt.login()
        rtir_rt.create_ticket(Queue=rtir_queue, Owner=rtir_creator, Subject=rtir_subject, Text=rtir_text)
        rtir_rt.logout()
    
    # Redirect to RTIR instance
    return redirect(rtir_url)

def createSlackAlert(esid):
    search = getHits(esid)
    for result in search['hits']['hits']:
        result = result['_source']
        message = result['message']
        description = str(message)    
        slack_url = parser.get('slack', 'slack_url')
        webhook_url = parser.get('slack', 'slack_webhook')
        slack_data = {'text': description}

        response = requests.post(
            webhook_url, data=json.dumps(slack_data),
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code != 200:
            raise ValueError(
            'Request to slack returned an error %s, the response is:\n%s'
            % (response.status_code, response.text)
        )
    
    # Redirect to Slack workspace
    return redirect(slack_url)

def createFIREvent(esid):
    search = getHits(esid)
    for result in search['hits']['hits']:
        result = result['_source']
        message = result['message']
        event_type = result['event_type']
        description = str(message)
        fir_api = '/api/incidents'
        fir_url = parser.get('fir', 'fir_url')
        fir_token = parser.get('fir', 'fir_token')
        actor = parser.get('fir', 'fir_actor')
        category = parser.get('fir', 'fir_category')
        confidentiality = parser.get('fir', 'fir_confidentiality')
        detection = parser.get('fir', 'fir_detection')
        plan = parser.get('fir', 'fir_plan')
        severity = parser.get('fir', 'fir_severity')
        subject = str('New ' + event_type + ' event from Security Onion!')
        
        headers = {
            'Authorization' : 'Token ' + fir_token ,
            'Content-type' : 'application/json'
        }
        
        response = requests.get(fir_url + fir_api, headers=headers, verify=False)
	
        data = {
            "actor": actor,
            "category": category,
            "confidentiality": confidentiality,
            "description": description,
            "detection": detection,
            "plan": plan,
            "severity": int(severity),
            "subject": subject
        }

        response = requests.post(fir_url + fir_api, headers=headers, data=json.dumps(data), verify=False)
    
    # Redirect to FIR instance
    return redirect(fir_url + '/events') 
