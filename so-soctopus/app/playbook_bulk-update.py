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

playbook_headers = {'X-Redmine-API-Key': parser.get("playbook", "playbook_key"), 'Content-Type': 'application/json'}
playbook_url = parser.get("playbook", "playbook_url")

updated_plays = dict()
play_update_counter = 0
play_new_counter = 0
play_noupdate_counter = 0

#Get current plays from Playbook
url = f"{playbook_url}/issues.json?tracker_id=4&limit=300"
playbook_plays = requests.get(url, headers=playbook_headers, verify=False).json()

#Create / Update the community Sigma repo
sigma_repo = f"sigma/README.md"
if os.path.exists(sigma_repo):
    git_status = subprocess.run(["git","--git-dir=sigma/.git", "pull"], stdout=subprocess.PIPE, encoding='ascii')
else:     
    git_status = subprocess.run(["git","clone", "https://github.com/Neo23x0/sigma.git"], stdout=subprocess.PIPE, encoding='ascii')

print (f"Community Repo Update status\n\n{git_status.stdout}\n\n")

'''
Next, loop through each sigma signature in the folder
Compare the title of the current signature against the current plays
If no match, then create a new play in playbook
If there is a match, compare a hash of the sigma:
    Hash matches --> no update needed
    Hash doesn't match --> update the play in playbook
Finally, print a summary of new or updated plays
'''
for filename in Path('./sigma/rules/windows/sysmon/').glob('**/*.yml'):
    print (f"\n\n{filename}")
    with open(filename) as fpi2:
        raw = fpi2.read()
    try:
        repojson = yaml.load(raw)
        for play in playbook_plays['issues']:
            if repojson['title'] == play['subject']:
                playbook_play = playbook.play_metadata(play['id'])
                sigma_raw = re.sub("{{collapse\(View Sigma\)|<pre><code class=\"yaml\">|</code></pre>|}}", "", playbook_play['sigma'])
                sigma_yaml = yaml.load(sigma_raw)
                repo_hash = hashlib.sha256(raw.strip().encode('utf-8')).hexdigest()
                play_hash = hashlib.sha256(sigma_raw.strip().encode('utf-8')).hexdigest()
                if repo_hash != play_hash:
                    #Update Play
                    play_update_counter += 1
                    updated_plays['updated'] = repojson['title']
                    print("Play Needs Update")
                    raw = f'{{{{collapse(View Sigma)\n<pre><code class="yaml">\n\n{raw}\n</code></pre>\n}}}}'
                    update_payload = {"issue": {"subject": playbook_play['title'],"project_id": 1, "tracker": "Play", "custom_fields": [\
                        {"id": 21, "name": "Sigma", "value": raw.strip()} ]}}
                    url = f"{playbook_url}/issues/{play['id']}.json"
                    r = requests.put(url, data=json.dumps(update_payload), headers=playbook_headers, verify=False)
                else: play_noupdate_counter += 1 
                break
        else:
            print('No Current Play - Create New Play in PB')
            play_new_counter += 1
            url = f"{playbook_url}/issues.json"
            payload = {"issue":{"project_id":1,"subject":"Example","tracker_id":6,"custom_fields":[{"value":"Comm-Win-Sysmon","name":"Playbook","id":24},{"value":raw,"name":"Sigma","id":21}]}}
            playbook_newplay = requests.post(url, headers=playbook_headers, data=json.dumps(payload), verify=False).json()
            time.sleep(.5)
    except Exception as e:
        print ('Error - Sigma Signature skipped \n' + str(e))

print (f"\n\n-= Update Summary =-\n\nSigma Community Repo:\n {git_status.stdout.strip()}\n\nUpdated Plays: {play_update_counter}\nNew Plays: {play_new_counter}\nNo Updates Needed: {play_noupdate_counter}\n")


'''
#Bulk Activate Plays
print ("Bulk Activating Plays")
url = f"{playbook_url}/issues.json?tracker_id=4&limit=300&status_id=1"
response_data = requests.get(url, headers=playbook_headers, verify=False).json()

for play in response_data['issues']:
   active_payload = {"issue":{"status_id":3}}
   print (play['id'])
   url = f"{playbook_url}/issues/{play['id']}.json"
   r = requests.put(url, data=json.dumps(active_payload), headers=playbook_headers, verify=False)
   print(r)
   time.sleep(1)

'''
