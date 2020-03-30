#!/usr/bin/env python
# -*- coding: utf-8 -*-
from helpers import getHits, getConn, doUpdate
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact
from pymisp import PyMISP
from grr_api_client import api
from grr import listProcessFlow, checkFlowStatus, downloadFlowResults
from requests.auth import HTTPBasicAuth
from flask import redirect, render_template, jsonify
from flask_wtf import FlaskForm
from forms import DefaultForm
from wtforms import StringField
from config import parser, es_index
import playbook
import json
import uuid
import sys
import rt
import requests
import os
import base64
import time
import jsonpickle
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

es_url = parser.get('es', 'es_url')
hive_url = parser.get('hive', 'hive_url')
hive_key = parser.get('hive', 'hive_key')
hive_verifycert = parser.getboolean('hive', 'hive_verifycert', fallback=False)


def hiveInit():
    return TheHiveApi(hive_url, hive_key, cert=hive_verifycert)


def createHiveAlert(esid):
    search = getHits(esid)
    # Hive Stuff
    # es_url = parser.get('es', 'es_url')
    hive_url = parser.get('hive', 'hive_url')
    hive_api = hiveInit()
    tlp = int(parser.get('hive', 'hive_tlp'))
    for result in search['hits']['hits']:

        # Get initial details
        message = result['_source']['message']
        es_id = result['_id']
        description = str(message)
        sourceRef = str(uuid.uuid4())[0:6]
        tags = ["SecurityOnion"]
        artifacts = []
        id = None
        host = str(result['_index']).split(":")[0]
        index = str(result['_index']).split(":")[1]
        event_type = result['_source']['event_type']

        if 'source_ip' in result['_source']:
            src = str(result['_source']['source_ip'])
        if 'destination_ip' in result['_source']:
            dst = str(result['_source']['destination_ip'])
        if 'source_port' in result['_source']:
            srcport = str(result['_source']['source_port'])
        if 'destination_port' in result['_source']:
            dstport = str(result['_source']['destination_port'])
        # NIDS Alerts
        if 'ids' in event_type:
            alert = result['_source']['alert']
            sid = str(result['_source']['sid'])
            category = result['_source']['category']
            sensor = result['_source']['sensor_name']
            masterip = str(es_url.split("//")[1].split(":")[0])
            tags.append("nids")
            tags.append(category)
            title = alert
            print(alert)
            sys.stdout.flush()
            # Add artifacts
            artifacts.append(AlertArtifact(dataType='ip', data=src))
            artifacts.append(AlertArtifact(dataType='ip', data=dst))
            artifacts.append(AlertArtifact(dataType='other', data=sensor))
            description = "`NIDS Dashboard:` \n\n <https://" + masterip + f"/kibana/app/kibana#/dashboard/ed6f7e20-e060-11e9-8f0c-2ddbf5ed9290?_g=(refreshInterval:(display:Off,pause:!f,value:0),time:(from:now-24h,mode:quick,to:now))&_a=(columns:!(_source),index:'*:{es_index}',interval:auto,query:(query_string:(analyze_wildcard:!t,query:'sid:" + sid + "')),sort:!('@timestamp',desc))> \n\n `IPs: `" + src + ":" + srcport + "-->" + dst + ":" + dstport + "\n\n `Signature:`" + alert + "\n\n `PCAP:` " + "https://" + masterip + "/kibana/app//sensoroni/securityonion/joblookup?redirectUrl=/sensoroni/&esid=" + es_id
        # Bro logs
        elif 'bro' in event_type:
            _map_key_type = {
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
                "sip": "SIP",
                "smb": "SMB",
                "smtp": "SMTP",
                "snmp": "SNMP",
                "ssh": "SSH",
                "ssl": "SSL",
                "syslog": "Syslog",
                "weird": "Weird",
                "x509": "X509"
            }

            bro_tag = event_type.strip('bro_')
            bro_tag_title = _map_key_type.get(bro_tag)
            title = str('New Bro ' + bro_tag_title + ' record!')

            if 'source_ip' in result['_source']:
                artifacts.append(AlertArtifact(dataType='ip', data=src))
            if 'destination_ip' in result['_source']:
                artifacts.append(AlertArtifact(dataType='ip', data=dst))
            if 'sensor_name' in result['_source']:
                sensor = str(result['_source']['sensor_name'])
                artifacts.append(AlertArtifact(dataType='other', data=sensor))
            if 'uid' in result['_source']:
                uid = str(result['_source']['uid'])
                title = str('New Bro ' + bro_tag_title + ' record! - ' + uid)
                artifacts.append(AlertArtifact(dataType='other', data=uid))
            if 'fuid' in result['_source']:
                fuid = str(result['_source']['fuid'])
                title = str('New Bro ' + bro_tag_title + ' record! - ' + fuid)
                artifacts.append(AlertArtifact(dataType='other', data=fuid))
            if 'id' in result['_source']:
                fuid = str(result['_source']['id'])
                title = str('New Bro ' + bro_tag_title + ' record! - ' + fuid)
                artifacts.append(AlertArtifact(dataType='other', data=fuid))

            tags.append('bro')
            tags.append(bro_tag)

        # Wazuh/OSSEC logs
        elif 'ossec' in event_type:
            agent_name = result['_source']['agent']['name']
            if 'description' in result['_source']:
                ossec_desc = result['_source']['description']
            else:
                ossec_desc = result['_source']['full_log']
            if 'ip' in result['_source']['agent']:
                agent_ip = result['_source']['agent']['ip']
                artifacts.append(AlertArtifact(dataType='ip', data=agent_ip))
                artifacts.append(AlertArtifact(dataType='other', data=agent_name))
            else:
                artifacts.append(AlertArtifact(dataType='other', data=agent_name))

            title = ossec_desc
            tags.append("wazuh")

        elif 'sysmon' in event_type:
            if 'ossec' in result['_source']['tags']:
                agent_name = result['_source']['agent']['name']
                agent_ip = result['_source']['agent']['ip']
                ossec_desc = result['_source']['full_log']
                artifacts.append(AlertArtifact(dataType='ip', data=agent_ip))
                artifacts.append(AlertArtifact(dataType='other', data=agent_name))
                tags.append("wazuh")
            elif 'beat' in result['_source']['tags']:
                agent_name = str(result['_source']['beat']['hostname'])
                if 'beat_host' in result['_source']:
                    try:
                        os_name = str(result['_source']['beat_host']['os']['name'])
                        artifacts.append(AlertArtifact(dataType='other', data=os_name))
                    except:
                        pass
                    try:
                        beat_name = str(result['_source']['beat_host']['name'])
                        artifacts.append(AlertArtifact(dataType='other', data=beat_name))
                    except:
                        pass
                if 'source_hostname' in result['_source']:
                    source_hostname = str(result['_source']['source_hostname'])
                    artifacts.append(AlertArtifact(dataType='fqdn', data=source_hostname))
                if 'source_ip' in result['_source']:
                    source_ip = str(result['_source']['source_ip'])
                    artifacts.append(AlertArtifact(dataType='ip', data=source_ip))
                if 'destination_ip' in result['_source']:
                    destination_ip = str(result['_source']['destination_ip'])
                    artifacts.append(AlertArtifact(dataType='ip', data=destination_ip))
                if 'image_path' in result['_source']:
                    image_path = str(result['_source']['image_path'])
                    artifacts.append(AlertArtifact(dataType='filename', data=image_path))
                if 'Hashes' in result['_source']['event_data']:
                    hashes = result['_source']['event_data']['Hashes']
                    for hash in hashes.split(','):
                        if hash.startswith('MD5') or hash.startswith('SHA256'):
                            artifacts.append(AlertArtifact(dataType='hash', data=hash.split('=')[1]))
                tags.append("beats")
            else:
                agent_name = ''
            title = "New Sysmon Event! - " + agent_name

        else:
            title = "New " + event_type + " Event From Security Onion"
        form = DefaultForm()
        artifact_string = jsonpickle.encode(artifacts)
        return render_template('hive.html', title=title, tlp=tlp, tags=tags, description=description,
                               artifact_string=artifact_string, sourceRef=sourceRef, form=form)


def sendHiveAlert(title, tlp, tags, description, sourceRef, artifact_string):
    tlp = int(parser.get('hive', 'hive_tlp'))

    hive_api = hiveInit()

    newtags = tags.strip('][').replace("'", "").split(', ')
    description = description.strip('"')
    artifacts = json.loads(artifact_string)

    # print(newtags)
    # Build alert
    hivealert = Alert(
        title=title,
        tlp=tlp,
        tags=newtags,
        description=description,
        type='external',
        source='SecurityOnion',
        sourceRef=sourceRef,
        artifacts=artifacts
    )

    # Send it off
    response = hive_api.create_alert(hivealert)
    if response.status_code == 201:
        print(json.dumps(response.json(), indent=4, sort_keys=True))
        print('')
        id = response.json()['id']

        # If running standalone / eval tell ES that we sent the alert
        # es_type = 'doc'
        # es_index = index
        # es_headers = {'Content-Type' : 'application/json'}
        # es_data = '{"script" : {"source": "ctx._source.tags.add(params.tag)","lang": "painless","params" : {"tag" : "Sent to TheHive"}}}'
        # update_es_event = requests.post(es_url + '/' + es_index + '/' + es_type + '/' + esid +  '/_update', headers=es_headers, data=es_data)
        # print(update_es_event.content)

    else:
        print('ko: {}/{}'.format(response.status_code, response.text))
        sys.exit(0)

    # Redirect to TheHive instance
    return redirect(hive_url + '/index.html#!/alert/list')


def createMISPEvent(esid):
    search = getHits(esid)
    # MISP Stuff
    misp_url = parser.get('misp', 'misp_url')
    misp_key = parser.get('misp', 'misp_key')
    misp_verifycert = parser.getboolean('misp', 'misp_verifycert', fallback=False)
    distrib = parser.get('misp', 'distrib')
    threat = parser.get('misp', 'threat')
    analysis = parser.get('misp', 'analysis')

    for result in search['hits']['hits']:
        result = result['_source']
        message = result['message']
        description = str(message)
        info = description

        def init(url, key):
            return PyMISP(url, key, ssl=misp_verifycert, debug=True)

        misp = init(misp_url, misp_key)

        event = misp.new_event(distrib, threat, analysis, info)
        event_id = str(event['Event']['id'])

        if 'source_ip' in result:
            data_type = "ip-src"
            source_ip = result['source_ip']
            misp.add_named_attribute(event_id, data_type, source_ip)

        if 'destination_ip' in result:
            data_type = "ip-dst"
            destination_ip = result['destination_ip']
            misp.add_named_attribute(event_id, data_type, destination_ip)

    # Redirect to MISP instance    
    return redirect(misp_url + '/events/index')


def createGRRFlow(esid, flow_name):
    search = getHits(esid)

    tlp = int(parser.get('hive', 'hive_tlp'))
    hive_api = hiveInit()

    grr_url = parser.get('grr', 'grr_url')
    grr_user = parser.get('grr', 'grr_user')
    grr_pass = parser.get('grr', 'grr_pass')
    grrapi = api.InitHttp(api_endpoint=grr_url,
                          auth=(grr_user, grr_pass))

    base64string = '%s:%s' % (grr_user, grr_pass)
    base64string = base64.b64encode(bytes(base64string, "utf-8"))
    authheader = "Basic %s" % base64string
    index_response = requests.get(grr_url, auth=HTTPBasicAuth(grr_user, grr_pass))
    csrf_token = index_response.cookies.get("csrftoken")
    headers = {
        "Authorization": authheader,
        "x-csrftoken": csrf_token,
        "x-requested-with": "XMLHttpRequest"
    }
    cookies = {
        "csrftoken": csrf_token
    }

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
                # flow_name = "ListProcesses"
                if client_id is None:
                    pass

                # Process flow and get flow id
                flow_id = listProcessFlow(client_id, grr_url, headers, cookies, grr_user, grr_pass)

                # Get status
                status = checkFlowStatus(client_id, grr_url, flow_id, headers, cookies, grr_user, grr_pass)

                # Keep checking to see if complete
                while status != "terminated":
                    time.sleep(15)
                    print("Flow not yet completed..watiing 15 secs before attempting to check status again...")
                    status = checkFlowStatus(client_id, grr_url, flow_id, headers, cookies, grr_user, grr_pass)

                # If terminated, run the download
                if status == "terminated":
                    downloadFlowResults(client_id, grr_url, flow_id, headers, cookies, grr_user, grr_pass)
                # print("Done!")

                # Run flow via API client
                # flow_obj = grrapi.Client(client_id)
                # flow_obj.CreateFlow(name=flow_name)
                title = "Test Alert with GRR Flow"
                description = str(message)
                sourceRef = str(uuid.uuid4())[0:6]
                tags = ["SecurityOnion", "GRR"]
                artifacts = []
                id = None
                filepath = "/tmp/soctopus/" + client_id + ".zip"
                artifacts.append(AlertArtifact(dataType='file', data=str(filepath)))

                # Build alert
                hivealert = Alert(
                    title=title,
                    tlp=tlp,
                    tags=tags,
                    description=description,
                    type='external',
                    source='SecurityOnion',
                    sourceRef=sourceRef,
                    artifacts=artifacts
                )

                # Send it off
                response = hive_api.create_alert(hivealert)

            if client_id:
                # Redirect to GRR instance
                return redirect(grr_url + '/#/clients/' + client_id + '/flows')
            else:
                return "No matches found for source or destination ip"


def createRTIRIncident(esid):
    search = getHits(esid)
    rtir_url = parser.get('rtir', 'rtir_url')
    rtir_api = parser.get('rtir', 'rtir_api')
    rtir_user = parser.get('rtir', 'rtir_user')
    rtir_pass = parser.get('rtir', 'rtir_pass')
    rtir_queue = parser.get('rtir', 'rtir_queue')
    rtir_creator = parser.get('rtir', 'rtir_creator')
    verify_cert = parser.getboolean('rtir', 'rtir_verifycert', fallback=False)

    for result in search['hits']['hits']:
        result = result['_source']
        message = result['message']
        description = str(message)
        event_type = result['event_type']
        rtir_subject = 'New ' + event_type + ' event from Security Onion!'
        rtir_text = description
        rtir_rt = rt.Rt(rtir_url + '/' + rtir_api, rtir_user, rtir_pass, verify_cert=verify_cert)
        rtir_rt.login()
        rtir_rt.create_ticket(Queue=rtir_queue, Owner=rtir_creator, Subject=rtir_subject, Text=rtir_text)
        rtir_rt.logout()

    # Redirect to RTIR instance
    return redirect(rtir_url)


def createSlackAlert(esid):
    search = getHits(esid)
    slack_url = parser.get('slack', 'slack_url')
    webhook_url = parser.get('slack', 'slack_webhook')
    for result in search['hits']['hits']:
        result = result['_source']
        message = result['message']
        description = str(message)
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
    fir_api = '/api/incidents'
    fir_url = parser.get('fir', 'fir_url')
    fir_token = parser.get('fir', 'fir_token')
    actor = parser.get('fir', 'fir_actor')
    category = parser.get('fir', 'fir_category')
    confidentiality = parser.get('fir', 'fir_confidentiality')
    detection = parser.get('fir', 'fir_detection')
    plan = parser.get('fir', 'fir_plan')
    severity = parser.get('fir', 'fir_severity')
    verify_cert = parser.getboolean('fir', 'fir_verifycert', fallback=False)

    for result in search['hits']['hits']:
        result = result['_source']
        message = result['message']
        event_type = result['event_type']
        description = str(message)

        subject = str('New ' + event_type + ' event from Security Onion!')

        headers = {
            'Authorization': 'Token ' + fir_token,
            'Content-type': 'application/json'
        }

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

        requests.post(fir_url + fir_api, headers=headers, data=json.dumps(data), verify=verify_cert)

    # Redirect to FIR instance
    return redirect(fir_url + '/events')


def playbookWebhook(webhook_content):
    """
    Process incoming playbook webhook.
    
    """
    action = webhook_content['payload']['action']
    issue_tracker_name = webhook_content['payload']['issue']['tracker']['name']
    issue_id = webhook_content['payload']['issue']['id']
    issue_status_name = webhook_content['payload']['issue']['status']['name']

    # if action == 'opened' and issue_tracker_name == 'Sigma Import':
    #    playbook.play_create(str(issue_id))
    if action == 'updated' and issue_tracker_name == 'Play':
        journal_details = webhook_content['payload']['journal']['details']
        detection_updated = False
        for item in journal_details:
            # Check to see if the Sigma field has changed
            if item['prop_key'] == '21':
                # Sigma field updated --> Call function - Update Play metadata
                playbook.play_update(issue_id)
                # Create/Update ElastAlert config
                if issue_status_name == "Active" and not detection_updated:
                    detection_updated = True
                    playbook.elastalert_update(issue_id)
                    playbook.navigator_update()
                    playbook.thehive_casetemplate_update(issue_id)
                elif issue_status_name == "Inactive" and not detection_updated:
                    detection_updated = True
                    playbook.elastalert_disable(issue_id)
                    playbook.navigator_update()

            # Check to see if the Play status has changed to Active or Inactive
            elif item['prop_key'] == 'status_id' and not detection_updated:
                if item['value'] == '3':
                    # Status = Active --> Enable EA & TheHive
                    detection_updated = True
                    playbook.elastalert_update(issue_id)
                    playbook.navigator_update()
                    playbook.thehive_casetemplate_update(issue_id)
                elif item['value'] == '4':
                    # Status = Inactive --> Disable EA
                    detection_updated = True
                    playbook.elastalert_disable(issue_id)
                    playbook.navigator_update()
    return "success"


def playbookSigmac(sigma):
    """
    Process incoming Sigma.
    
    """
    esquery = playbook.sigmac_generate(sigma)

    return esquery


def playbookCreatePlay(sigma_raw, sigma_dict):
    """
    Process incoming Sigma Yaml.
    
    """
    play_data = playbook.play_create(sigma_raw, sigma_dict)

    return jsonify(play_data)


def createStrelkaScan(esid):
    search = getHits(esid)
    for result in search['hits']['hits']:
        result = result['_source']
        message = result['message']
        event_type = result['event_type']
        extracted_file = result['extracted']
        conn_id = result['uid'][0]
        sensorsearch = getConn(conn_id)

        for result in sensorsearch['hits']['hits']:
            result = result['_source']
            sensor = result['sensor_name'].rsplit('-', 1)[0]
            strelka_scan_drop = "echo " + sensor + "," + extracted_file + " >>  /tmp/soctopus/strelkaq.log"
            os.system(strelka_scan_drop)

            return render_template('strelka.html', extracted_file=extracted_file, sensor=sensor)


def showESResult(esid):
    search = getHits(esid)
    for result in search['hits']['hits']:
        esindex = result['_index']
        result = result['_source']
        # print(result)

    return render_template("result.html", result=result, esindex=esindex)


class DefaultForm(FlaskForm):
    esindex = StringField('esindex')
    esid = StringField('esid')


def eventModifyFields(esid):
    search = getHits(esid)
    for result in search['hits']['hits']:
        esindex = result['_index']
        result = result['_source']
        tags = result['tags']
        form = DefaultForm()
    return render_template('update_event.html', result=result, esindex=esindex, esid=esid, tags=tags, form=form)


def eventUpdateFields(esindex, esid, tags):
    doUpdate(esindex, esid, tags)
    return showESResult(esid)


def processHiveReq(webhook_content):
    api = hiveInit()
    event_details = getHiveStatus(webhook_content)
    event_id = event_details.split(' ')[0]
    event_status = event_details.split(' ')[1]
    auto_analyze_alerts = parser.get('cortex', 'auto_analyze_alerts')

    # Run analyzers before case import
    if event_status == "alert_creation":
        if auto_analyze_alerts == "yes":
            sys.stdout.flush()
            alert_id = webhook_content['objectId']
            observables = webhook_content['object']['artifacts']
            analyzeAlertObservables(alert_id, observables)

    # Check to see if new case creation
    # if event_status == "case_creation":
    #    try:
    #        observables = api.get_case_observables(case_id).json()
    #    except:
    #        pass
    #    else:
    #        analyzeCaseObservables(observables)

    # Check to see if we are creating a new task
    if event_status == "case_task_creation":
        headers = {
            'Authorization': 'Bearer ' + hive_key
        }
        task = webhook_content
        task_id = webhook_content['objectId']
        task_status = "InProgress"
        task_group = webhook_content['object']['group']
        task_case = webhook_content['object']['_parent']
        task_title = webhook_content['object']['title']
        # task_desc = webhook_content['object']['description']

        # Check the task to see if it matches our conventionm for auto-analyze tasks (via Playbook, etc)
        if "Analyzer" in task_title:
            analyzer_minimal = task_title.split(" - ")[1]
            enabled_analyzers = getCortexAnalyzers()
            supported_analyzers = parser.get('cortex', 'supported_analyzers').split(",")
            if analyzer_minimal in supported_analyzers:
                # Start task
                response = requests.patch(hive_url + '/api/case/task/' + task_id, headers=headers,
                                          data={'status': task_status}, verify=hive_verifycert)
                # Get observables related to case
                observables = api.get_case_observables(task_case).json()
                for analyzer in enabled_analyzers:
                    if analyzer_minimal in analyzer['name']:
                        for cortexId in analyzer['cortexIds']:
                            # Look through all of our observables
                            for observable in observables:
                                # Check to see if observable type supported by analyzer
                                if observable['dataType'] in analyzer['dataTypeList']:
                                    # Run analyzer
                                    api.run_analyzer(cortexId, observable['id'], analyzer['id'])
                                    # analyzeCaseObservables(observables)
                # Add task log
                headers = {
                    'Authorization': 'Bearer ' + hive_key,
                    'Content-Type': 'application/json'
                }
                task_log = "Automation - Ran " + analyzer_minimal + " analyzer."
                data = {'message': task_log}
                response = requests.post(hive_url + '/api/case/task/' + task_id + '/log', headers=headers,
                                         data=json.dumps(data), verify=hive_verifycert)

                # Close task
                task_status = "Completed"
                response = requests.patch(hive_url + '/api/case/task/' + task_id, headers=headers,
                                          data={'status': task_status}, verify=hive_verifycert)

    sys.stdout.flush()

    return "success"


# def postAlertObservables(analyzer_results):
#   for result in analyzer_results:
#       print(result)
#       sys.stdout.flush()
#   return "OK"
def analyzeAlertObservables(alert_id, observables):
    """
    Analyze TheHive observables
    """
    alert_id = alert_id
    cortex_url = parser.get('cortex', 'cortex_url')
    cortex_key = parser.get('cortex', 'cortex_key')

    api = hiveInit()
    analyzers = getCortexAnalyzers()
    for analyzer in analyzers:
        # Get our list of Cortex servers (IDs)
        for cortexId in analyzer['cortexIds']:
            # Look through all of our observables
            for observable in observables:
                # Check to see if observable type supported by analyzer
                if observable['dataType'] in analyzer['dataTypeList']:
                    headers = {
                        'Authorization': 'Bearer ' + cortex_key,
                        'Content-Type': 'application/json'
                    }

                    data = {
                        "data": observable['data'],
                        "dataType": observable['dataType']
                    }
                    # Run analyzer
                    startjob = requests.post(cortex_url + '/api/analyzer/' + analyzer['id'] + '/run', headers=headers,
                                             data=json.dumps(data), verify=hive_verifycert)
                    wait_interval = '10second'
                    job_id = startjob.json()['id']
                    headers = {
                        'Authorization': 'Bearer ' + cortex_key
                    }

                    getresults = requests.get(cortex_url + '/api/job/' + job_id + '/waitreport?atMost=' + wait_interval,
                                              headers=headers, verify=hive_verifycert)

                    analyzer_results = getresults.json()
                    job_status = analyzer_results['status']
                    if job_status == "Success":
                        level = analyzer_results['report']['summary']['taxonomies'][0]['level']
                        customFields = {"customFields": {}}
                        reputation = dict(order=1, string=level)
                        customFields['customFields']['reputation'] = reputation
                        headers = {
                            'Authorization': 'Bearer ' + hive_key,
                            'Content-Type': 'application/json'
                        }
                        data = json.dumps(customFields)
                        addcustomfields = requests.patch(hive_url + '/api/alert/' + alert_id, headers=headers,
                                                         data=data, verify=hive_verifycert)
                    else:
                        pass
    return "OK"


def getHiveStatus(webhook_content):
    """
    Process incoming TheHive webhook
    """

    operation = webhook_content['operation']
    object_type = webhook_content['objectType']
    object = webhook_content['object']
    id = object['id']
    status = str(object_type).lower() + "_" + str(operation).lower()
    sys.stdout.flush()
    return '{} {}'.format(id, status)


def getCortexAnalyzers():
    headers = {
        'Authorization': 'Bearer ' + hive_key
    }

    response = requests.get(hive_url + '/api/connector/cortex/analyzer', headers=headers, verify=hive_verifycert)
    analyzers = json.loads(response.text)
    return analyzers
