#!/usr/bin/env python
# -*- coding: utf-8 -*-
from config import parser
import json
import os
from time import gmtime, strftime
import re
import shutil
import subprocess
import uuid

import fileinput
import requests
import ruamel.yaml
yaml = ruamel.yaml.YAML(typ='safe')


playbook_headers = {'X-Redmine-API-Key': parser.get("playbook", "playbook_key"), 'Content-Type': 'application/json'}
playbook_url = parser.get("playbook", "playbook_url")

hive_headers = {'Authorization': f"Bearer {parser.get('hive', 'hive_key')}",'Accept': 'application/json, text/plain', 'Content-Type': 'application/json;charset=utf-8'}

def navigator_update():
    #Get play data from Redmine
    url = f"{playbook_url}/issues.json?status_id=3"
    response_data = requests.get(url, headers=playbook_headers, verify=False).json()

    technique_payload = []
    for play in response_data['issues']:
        for custom_field in play['custom_fields']:
            if custom_field['id'] == 27 and (custom_field['value']):
                    technique_id = custom_field['value'][0]
                    technique_payload.append({"techniqueID":technique_id,"color":"#5AADFF","comment":"","enabled":"true","metadata":[]})

    payload = {"name":"Playbook","version":"2.1","domain":"mitre-enterprise","description":f"Current Coverage of Playbook - Updated {strftime('%Y-%m-%d %H:%M', gmtime())}","filters":{"stages":["act"],"platforms":["windows"]},"sorting":0,"viewMode":0,"hideDisabled":"false","techniques":technique_payload,"gradient":{"colors":["#ff6666","#ffe766","#8ec843"],"minValue":0,"maxValue":100},"metadata":[],"showTacticRowBackground":"false","tacticRowBackground":"#dddddd","selectTechniquesAcrossTactics":"true"}
    nav_layer = open('/etc/playbook/nav_layer_playbook.json', 'w')
    print(json.dumps(payload), file=nav_layer)
    nav_layer.close()
                   
def thehive_casetemplate_update(issue_id):

    play = play_metadata(issue_id)
    
    #Check to see if there are any tasks - if so, get them formatted
    tasks = []
    if play.get('tasks'):
        task_order = 0
        for task_title, task_desc in play.get('tasks').items():
            task_order += 1
            tasks.append ({"order":task_order,"title":task_title,"description":task_desc})
    else: tasks = []

    #Build the case template
    case_template = {"name":play['playid'],"severity":2,"tlp":3,"metrics":{},"customFields":{\
        "playObjective":{"string":play['description']},\
        "playbookLink":{"string": f"{playbook_url}/issues/{issue_id}" }},\
        "description":play['description'],\
        "tasks":tasks}

    # Is there a Case Template already created?
    if play['hiveid']:
        # Case Template exists - let's update it
        url = f"{parser.get('hive', 'hive_url')}/api/case/template/{play['hiveid']}"
        r = requests.patch(url, data=json.dumps(case_template),headers=hive_headers, verify=False).json()

    else:
        # Case Template does not exist - let's create it
        url = f"{parser.get('hive', 'hive_url')}/api/case/template"
        r = requests.post(url, data=json.dumps(case_template),headers=hive_headers, verify=False).json()

        # Update Play (on Redmine) with Template ID
        url = f"{playbook_url}/issues/{issue_id}.json"
        data = '{"issue":{"custom_fields":[{"id":8,"value":"' + r['id'] + '"}]}}'
        r = requests.put(
            url, data=data, headers=playbook_headers, verify=False)

    return 200, "success"


def elastalert_update(issue_id):
    play = play_metadata(issue_id)

    play_file = f"/etc/playbook-rules/{play['playid']}.yaml"

    if os.path.exists(play_file):
        os.remove(play_file)

    try:
        if play['product'] == 'osquery':
            shutil.copy('/etc/playbook-rules/osquery.template', play_file)
        else:
            shutil.copy('/etc/playbook-rules/generic.template', play_file)
        for line in fileinput.input(play_file, inplace=True):
            line = re.sub(r'name:\s\S*', f"name: {play['title']}", line.rstrip())
            line = re.sub(r'query:\s\'.*\'', f"query: \'{play['esquery']}\'", line.rstrip())
            line = re.sub(r'caseTemplate:.*', f"caseTemplate: '{play['playid']}'", line.rstrip())
            print(line)

    except FileNotFoundError:
        print("ElastAlert Template File not found")

    return 200, "success"


def elastalert_disable(issue_id):
    play = play_metadata(issue_id)
    play_file = f"/etc/playbook-rules/{play['playid']}.yaml"
    if os.path.exists(play_file):
        os.remove(play_file)
    return 200, "success"


def play_create(issue_id):
    play = play_metadata(issue_id)
    
    play_id = uuid.uuid4().hex

    payload = {"issue": {"subject": play['title'],"project_id": 1,"status":"Draft", "tracker": "Play", "custom_fields": [\
    {"id": 6, "name": "Title", "value": play['title']},\
    {"id": 24, "name": "Playbook", "value": "External"},\
    {"id": 15, "name": "ES Query", "value": play['esquery'] },\
    {"id": 23, "name": "Level", "value": play['level']},\
    {"id": 25, "name": "Product", "value": play['product']},\
    {"id": 2, "name": "Description", "value": play['description']},\
    {"id": 17, "name": "Author", "value":play['author']},\
    {"id": 16, "name": "References", "value": play['references']},\
    {"id": 7, "name": "Analysis", "value": f"{play['falsepositives']}{play['logfields']}"},\
    {"id": 28, "name": "PlayID", "value": play_id[0:9]},\
    {"id": 27, "name": "Tags", "value": play['tags']},\
    {"id": 21, "name": "Sigma", "value": play['sigma']}\
    ]}}
    
    # POST/PUT payload to Redmine to create play
    url = f"{playbook_url}/issues.json"
    r = requests.post(url, data=json.dumps(payload),
                      headers=playbook_headers, verify=False)

    if r.status_code == 201:
        payload = '{"issue":{"project_id":1,"tracker":"Play","custom_fields":[{"id":29,"name":"Import Status","value":"Successful - PlayID: ' + play_id[0:9] + '"}]} }'
        url = f"{playbook_url}/issues/{issue_id}.json"
        r = requests.put(url, data=payload,
                         headers=playbook_headers, verify=False)
        print(r)
    else:
        payload = '{"issue":{"project_id":1,"tracker":"Play","custom_fields":[{"id":29,"name":"Import Status","value":"Not Successful-' + str(
            r.status_code) + '"}]} }'
        url = f"{playbook_url}/issues/{issue_id}.json"
        r = requests.put(url, data=payload,
                         headers=playbook_headers, verify=False)

    return 'success', 200


def play_update(issue_id):
    play = play_metadata(issue_id)

    payload = {"issue": {"subject": play['title'],"project_id": 1, "tracker": "Play", "custom_fields": [\
    {"id": 6, "name": "Title", "value": play['title']},\
    {"id": 23, "name": "Level", "value": play['level']},\
    {"id": 15, "name": "ES Query", "value": play['esquery'] },\
    {"id": 25, "name": "Product", "value": play['product']},\
    {"id": 2, "name": "Description", "value": play['description']},\
    {"id": 17, "name": "Author", "value":play['author']},\
    {"id": 16, "name": "References", "value": play['references']},\
    {"id": 7, "name": "Analysis", "value": f"{play['falsepositives']}{play['logfields']}"},\
    {"id": 27, "name": "Tags", "value": play['tags']} ]}}

    url = f"{playbook_url}/issues/{issue_id}.json"
    r = requests.put(url, data=json.dumps(payload), headers=playbook_headers, verify=False)
    print(r)

    return 'success', 200


def play_metadata(issue_id):

    play = dict()
    url = f"{playbook_url}/issues/{issue_id}.json"

    r = requests.get(url, headers=playbook_headers, verify=False).json()

    for item in r['issue']['custom_fields']:
        if item['name'] == "Sigma":
            sigma_raw = item['value']
        elif item['name'] == "HiveID":
            play['hiveid'] = item['value']
        elif item['name'] == "PlayID":
            play['playid'] = item['value']

    sigma_raw = re.sub(
        "{{collapse\(View Sigma\)|<pre><code class=\"yaml\">|</code></pre>|}}", "", sigma_raw)
    sigma = yaml.load(sigma_raw)

    # Call sigmac tool to generate ES Query
    dump = open('dump.txt', 'w')
    print(sigma, file=dump)
    dump.close()

    product = sigma['logsource']['product'] if 'product' in sigma['logsource'] else 'none'

    if product == 'osquery':
        esquery = subprocess.run(["sigmac","-t", "es-qs", "dump.txt", "-c", "securityonion-osquery.yml"], stdout=subprocess.PIPE, encoding='ascii')
    else:
        esquery = subprocess.run(["sigmac","-t", "es-qs", "dump.txt", "-c", "securityonion-network.yml", "-c", "securityonion-winlogbeat.yml"], stdout=subprocess.PIPE, encoding='ascii')
    
    #esquery = subprocess.run(["sigmac","-t", "es-qs", "dump.txt", f"{sigma_config}"], stdout=subprocess.PIPE, encoding='ascii')
    #esquery = subprocess.run(["sigmac","-t", "es-qs", "dump.txt", "-c", "filebeat-defaultindex"], stdout=subprocess.PIPE, encoding='ascii')
    #sigma_config = '"-c","securityonion-osquery.yml"' if play.get('product') == 'osquery'\
    #else '"-c","securityonion-network.yml","-c", "securityonion-winlogbeat.yml"'

    # Prep ATT&CK Tags
    tags = re.findall(r"t\d{4}", ''.join(
        sigma.get('tags'))) if sigma.get('tags') else ''
    play['tags'] = [element.upper() for element in tags]


    print (sigma.get('tasks'))

    return {
        'playid': play.get('playid'),
        'hiveid': play.get('hiveid'),
        'references': '\n'.join(sigma.get('references')) if sigma.get('references') else 'none',
        'title': sigma.get('title') if sigma.get('title') else 'none',
        'description': sigma.get('description') if sigma.get('description') else 'none',
        'level': sigma.get('level') if sigma.get('level') else 'none',
        'tags': play['tags'],
        'sigma': f'{{{{collapse(View Sigma)\n<pre><code class="yaml">\n\n{sigma_raw}\n</code></pre>\n}}}}',
        'author': sigma.get('author') if sigma.get('author') else 'none',
        'falsepositives': '_False Positives_\n' + '\n'.join(sigma.get('falsepositives')) if sigma.get('falsepositives') else '_False Positives_\n Unknown',
        'logfields': '\n\n_Interesting Log Fields_\n' + '\n'.join(sigma.get('fields')) if sigma.get('fields') else '',
        'esquery': esquery.stdout.strip(),
        'tasks': sigma.get('tasks'),
        'product': product
    }
