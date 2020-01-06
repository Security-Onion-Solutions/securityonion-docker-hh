import json
import os
import re
import glob
import time
import hashlib
from pathlib import Path
import urllib3
import subprocess

import requests
import ruamel.yaml
from config import parser
import playbook
urllib3.disable_warnings()
yaml = ruamel.yaml.YAML(typ='safe')

updated_plays = dict()
play_update_counter = 0
play_new_counter = 0
play_noupdate_counter = 0
plays = []
offset = 0

playbook_headers = {'X-Redmine-API-Key': parser.get("playbook", "playbook_key"), 'Content-Type': 'application/json'}
playbook_url = parser.get("playbook", "playbook_url")

#Get all the current plays from Playbook
url = f"{playbook_url}/issues.json?offset=0&tracker_id=4&limit=100"
response = requests.get(url, headers=playbook_headers, verify=False).json()

for i in response['issues']:  
    plays.append(i)

while offset < response['total_count']:
    offset += 100
    url = f"{playbook_url}/issues.json?offset={offset}&tracker_id=4&limit=100"
    response = requests.get(url, headers=playbook_headers, verify=False).json()
    print (f"offset: {offset}")  
    for i in response['issues']:
        plays.append(i)

print (len(plays))


#Create / Update the community Sigma repo
sigma_repo = f"sigma/README.md"
if os.path.exists(sigma_repo):
    git_status = subprocess.run(["git","--git-dir=sigma/.git", "--work-tree=sigma", "pull"], stdout=subprocess.PIPE, encoding='ascii')
else:     
    git_status = subprocess.run(["git","clone", "https://github.com/Neo23x0/sigma.git"], stdout=subprocess.PIPE, encoding='ascii')


def update_play(raw, repojson, playbook_name):
    for play in plays:
        #print (repojson['id'])
        if repojson['title'] == play['subject']:
            playbook_play = playbook.play_metadata(play['id'])
            sigma_raw = re.sub("{{collapse\(View Sigma\)|<pre><code class=\"yaml\">|</code></pre>|}}", "", playbook_play['sigma'])
            sigma_yaml = yaml.load(sigma_raw)
            repo_hash = hashlib.sha256(raw.strip().encode('utf-8')).hexdigest()
            play_hash = hashlib.sha256(sigma_raw.strip().encode('utf-8')).hexdigest()
            if repo_hash != play_hash:
                #Update Play
                play_status = "updated"
                updated_plays['updated'] = repojson['title']
                print("Play Needs Update")
                raw = f'{{{{collapse(View Sigma)\n<pre><code class="yaml">\n\n{raw}\n</code></pre>\n}}}}'
                update_payload = {"issue": {"subject": playbook_play['title'],"project_id": 1, "status":"Disabled", "tracker": "Play", "custom_fields": [\
                    {"id": 21, "name": "Sigma", "value": raw.strip()} ]}}
                url = f"{playbook_url}/issues/{play['id']}.json"
                print (update_payload)
                r = requests.put(url, data=json.dumps(update_payload), headers=playbook_headers, verify=False)
                print (r)
            else: play_status = "nop" 
            break
    else:
        print('No Current Play - Create New Play in PB')
        play_status = "new"
        url = f"{playbook_url}/issues.json"
        payload = {"issue":{"project_id":1,"subject":"Example","tracker_id":6,"custom_fields":[{"value":playbook_name,"name":"Playbook","id":24},{"value":raw,"name":"Sigma","id":21}]}}
        playbook_newplay = requests.post(url, headers=playbook_headers, data=json.dumps(payload), verify=False).json()
        time.sleep(.9)
        
    return play_status


'''
Next, loop through each sigma signature in the folder
Compare the id of the current signature against the current plays
If no match, then create a new play in playbook
If there is a match, compare a hash of the sigma:
    Hash matches --> no update needed
    Hash doesn't match --> update the play in playbook
Finally, print a summary of new or updated plays
'''

# Possible options - Windows folder only: sysmon, malware, other, powershell, process_creation
#ruleset_categories = ['sysmon','malware','other','powershell','process_creation']
ruleset_categories = ['sysmon']

for folder in ruleset_categories:
    ruleset_path = f"./sigma/rules/windows/{folder}"
    for filename in Path(ruleset_path).glob('**/*.yml'):
        print (f"\n\n{filename}")
        with open(filename) as fpi2:
            raw = fpi2.read()
        try:
            repojson = yaml.load(raw)
            if folder == 'process_creation': folder = 'proc'
            play_status = update_play(raw, repojson, f"comm-win-{folder}")
            print (play_status)
            if play_status == "updated": play_update_counter += 1
            elif play_status == "new": play_new_counter += 1
            elif play_status == "nop": play_noupdate_counter += 1
        except Exception as e:
            print ('Error - Sigma Signature skipped \n' + str(e))

print (f"\n\n-= Update Summary =-\n\nSigma Community Repo:\n {git_status.stdout.strip()}\n\nUpdated Plays: {play_update_counter}\nNew Plays: {play_new_counter}\nNo Updates Needed: {play_noupdate_counter}\n")
