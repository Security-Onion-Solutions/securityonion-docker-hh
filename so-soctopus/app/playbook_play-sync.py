import json
import urllib3
import os
import time

import requests
from config import parser
import playbook
urllib3.disable_warnings()

active_elastalert_counter = 0
active_hive_counter = 0
inactive_elastalert_counter = 0

playbook_headers = {'X-Redmine-API-Key': parser.get(
    "playbook", "playbook_key"), 'Content-Type': 'application/json'}
playbook_url = parser.get("playbook", "playbook_url")

# Get active plays from Playbook
url = f"{playbook_url}/issues.json?tracker_id=4&limit=200&status_id=3"
active_plays = requests.get(url, headers=playbook_headers, verify=False).json()


for play in active_plays['issues']:
    play_hiveid = None

    for item in play['custom_fields']:
        if item['name'] == "PlayID":
            play_id = item['value']
        elif item['name'] == "HiveID":
            play_hiveid = item['value']

    print(f"\n\n{play_id} -- {play_hiveid}")

    play_file = f"/etc/playbook-rules/{play_id}.yaml"
    if os.path.exists(play_file):
        print('All Good - Elastalert Config Exists')
    else:
        print('Warning - Elastalert Config Doesnt Exist')
        active_elastalert_counter += 1
        playbook.elastalert_update(play['id'])
        time.sleep(.5)

    if (play_hiveid == "") or (play_id is None):
        print('Warning - HiveID doesnt exist')
        active_hive_counter += 1
        playbook.thehive_casetemplate_update(play['id'])
    else:
        print('All Good - HiveID Exists')


url = f"{playbook_url}/issues.json?tracker_id=4&limit=300&status_id=4"
inactive_plays = requests.get(
    url, headers=playbook_headers, verify=False).json()

for play in inactive_plays['issues']:

    for item in play['custom_fields']:
        if item['name'] == "PlayID":
            play_id = item['value']

    print(f"\n\n{play_id}")

    play_file = f"/etc/playbook-rules/{play_id}.yaml"
    if os.path.exists(play_file):
        print('Inactive Warning - Elastalert Config Exists')
        os.remove(play_file)
        inactive_elastalert_counter += 1

print(f"\n\n-= Maintenance Summary =-\n\n"
      f"Active Plays: {active_plays['total_count']}"
      f"\n-----------------\n"
      f"Missing ElastAlert Configs: {active_elastalert_counter}\n"
      f"Missing HiveIDs: {active_hive_counter}\n\n"
      f"Inactive Plays: {inactive_plays['total_count']}\n"
      f"-----------------\n"
      f"Out of Sync ElastAlert Configs: {inactive_elastalert_counter}")
