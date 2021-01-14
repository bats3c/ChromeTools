#!/usr/bin/env python3

import os
import sys
import yara
import importlib

from urllib.parse import unquote
from prettytable import PrettyTable

all_secrets = []
current_request = ""

def print_info(text):
    print("\033[34m[i]\033[0m", text)

def print_good(text):
    print("\033[92m[+]\033[0m", text)

def print_gold(text):
    print("\033[33m" + text + "\033[0m")

def usage():
    print("./hunt.py <dump>")
    exit(1)

def parse_args():
    data = {}

    if len(sys.argv) == 1:
        usage()

    data['dumpfile'] = sys.argv[1]

    return data

def parse_dump_and_stats(filename):
    info = {}

    with open(filename, 'rb') as file:
        data = file.read().split(b'\r\n\a\r\n\a')
    
    info['pkts'] = data
    info['pktcount'] = len(data)

    return info

def _yara_callback(scan_info):
    global all_secrets

    if scan_info['matches'] == True:
        plugin = scan_info['meta']['plugin']
        plugins = importlib.import_module('plugins')

        secrets = eval(f"plugins.{plugin}(current_request)")

        if secrets not in all_secrets and secrets is not None: 
            all_secrets.append(secrets)

    else: return


def hunt_for_secrets(count, reqs):
    global current_request

    secrets = {}

    for rule in os.listdir('rules/'):
        rules = yara.compile('rules/' + rule)

        for request in reqs:
            current_request = request
            matches = rules.match(data=request, callback=_yara_callback)

def couldnt_find_secrets():
    pass

def display_secrets():
    if len(all_secrets) == 1: print_good(f"Found {len(all_secrets)} secret")
    else: print_good(f"Found {len(all_secrets)} secrets")

    for secret in all_secrets:
        print("----------------------------------------------------")
        for key in secret:
            print_gold(f"{key}: {unquote(secret[key])}")
        print("----------------------------------------------------")

if __name__ == "__main__":

    args = parse_args()

    info = parse_dump_and_stats(args['dumpfile'])

    print_info(f"Scanning {info['pktcount']} requests...")

    hunt_for_secrets(info['pktcount'], info['pkts'])

    if len(all_secrets) != 0:
        display_secrets()
    else:
        couldnt_find_secrets()