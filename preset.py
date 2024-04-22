#!/usr/bin/python3
# Cisco Cyber Vision V4.0
# Device Management
import argparse
from collections import defaultdict
import csv
import sys

import cvconfig
import api

import json

def main():
    parser = argparse.ArgumentParser(prog="preset.py",
                                     description="Preset Management")
    # Options parsing
    parser.add_argument("--token", dest="token", help="Use this token")
    parser.add_argument("--center-ip", dest="center_ip",
                        help="Specified the center FQDN or IPv4 address"
                        " (default:'cybervision')")
    parser.add_argument("--center-port", dest="center_port",
                        help="Specified the center port (default: %d)"%cvconfig.center_port, 
                        default=cvconfig.center_port)
    parser.add_argument("--proxy", dest="proxy",
                        help="Specified the proxy to use (default: %s)"%cvconfig.proxy, 
                        default=cvconfig.proxy)
    parser.add_argument("--encoding", dest="csv_encoding",
                        help="CSV file encoding, default is %s" % cvconfig.csv_encoding)
    parser.add_argument("--delimiter", dest="csv_delimiter",
                        help="CSV file delimiter, default is %s" % cvconfig.csv_delimiter)
    
    parser.add_argument("--filename", dest="filename", help="Use this filename", default="presets.csv")
    # Main Command Parsing
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument("--export",
                               help="Export all presets into a CSV file\n",
                               action="store_true", default=False, dest="command_export")
    command_group.add_argument("--import",
                               help="Import presets from a CSV file\n",
                               action="store_true", default=False, dest="command_import")


    args = parser.parse_args()

    # Handle Cybervision configuration
    token = set_conf(args.token, cvconfig.token)
    center_ip = set_conf(args.center_ip, cvconfig.center_ip)
    center_port = set_conf(args.center_port, cvconfig.center_port)
    proxy = set_conf(args.proxy, cvconfig.proxy)
    csv_encoding = set_conf(args.csv_encoding, cvconfig.csv_encoding)
    csv_delimiter = set_conf(args.csv_delimiter, cvconfig.csv_delimiter)

    if not token or not center_ip:
        print("TOKEN and CENTER_IP are mandatory, check cvconfig.py or us --token/--center-ip")

    if args.command_export:
        return preset_export(center_ip, center_port, token, proxy, args.filename,csv_delimiter, csv_encoding)
    elif args.command_import:
        return preset_import(center_ip, center_port, token, proxy, args.filename, csv_delimiter, csv_encoding)
    
    parser.print_help()

def set_conf(arg,conf):
    if arg and arg != conf:
        return arg
    return conf
 
def preset_export(center_ip, center_port, token, proxy, filename,csv_delimiter, csv_encoding):
    with api.APISession(center_ip, center_port, token, proxy) as session:
        presets = api.get_route(session, '/api/3.0/presets')
        count_exported = 0
        with open(filename, 'w', encoding=csv_encoding) as csvfile:
            fieldnames = ['preset-id','preset-name','preset-description','preset-tags','preset-groups',
                        'preset-sensors','preset-centers','preset-networks','preset-risk-scores','preset-search']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=csv_delimiter)
            writer.writeheader()
            for p in presets:
                if not p['custom']:
                    continue
                #print(json.dumps(p, indent=4, sort_keys=True))
                count_exported = count_exported + 1
                # {'id': '347e7318-4407-4e46-97b6-e3606b8024c5', 'label': 'All data', 
                # 'description': 'xxxx for more accurate findings.', 'custom': False, 
                # 'imported': False, 'creatorEmail': '', 'activeDiscoveryEnabled': False, 
                # 'activeDiscoveryProtocols': [{'id': 'enip', 'enabled': False}, {'id': 's7discovery', 'enabled': False}, {'id': 'profinet', 'enabled': False}, {'id': 'icmpv6', 'enabled': False}], 
                # 'activeDiscoverySensors': [], 
                # 'lastUpdate': 1619525141936, 
                # 'filters': {'tags': [], 'groups': [], 'sensors': [], 'centers': [], 'networks': [], 'riskScores': []}, 
                # 'componentTagless': 'indeterminate', 'activityTagless': 'indeterminate', 'groupless': 'indeterminate', 'priority_order': 1, 
                # 'badges': [{'id': 'e30e0c18-06cb-47fc-a8bd-da450b834540', 'iconKey': 'organize', 'label': 'Organize', 'description': 'Best preset to organize your network'}], 
                # 'category': {'id': 'b5339246-c32a-5f85-9ed5-aa430a6d9d8e', 'label': 'Basics'}, 'search': '', 'baselines': [], 'operationalStarred': False, 'securityStarred': False}
                row = {}
                row['preset-id'] = p['id']
                row['preset-name'] = p['label']
                if 'description' in p:
                    row['preset-description'] = p['description']
                row['preset-tags'] = p['filters']['tags']
                row['preset-groups'] = p['filters']['groups']
                row['preset-sensors'] = p['filters']['sensors']
                row['preset-centers'] = p['filters']['centers']
                row['preset-networks'] = p['filters']['networks']
                row['preset-risk-scores'] = p['filters']['riskScores']
                row['preset-search'] = p['search']
                writer.writerow(row)
            print(f"LOG: Exported {count_exported} presets into '{filename}'")
    return

def preset_import(center_ip, center_port, token, proxy, filename,csv_delimiter, csv_encoding):
    with open(filename, 'r') as csvfile:
        with api.APISession(center_ip, center_port, token, proxy) as session:            
            reader = csv.DictReader(csvfile, delimiter=csv_delimiter)
            for row in reader:
                if not 'preset-name' in row or not row['preset-name']:
                    continue

                print(f"LOG: Preset '{row['preset-name']}' - Creating...")
                route = f"/api/3.0/presets"
                json = {
                    "label": row['preset-name'],
                    "description": row['preset-description'],
                    "filters": {
                        "tags": row['preset-tags'],
                        #"groups": row['preset-groups'],
                        #"sensors": row['preset-sensors'],
                        #"centers": row['preset-centers'],
                        #"networks": row['preset-networks'],
                        #"riskScores": row['preset-risk-scores'],                        
                    },
                    #"search": row['preset-search']
                }
                ret = api.post_route(session, route, json)
                if ret.status_code != 200:
                    print(f"ERROR: Calling [POST] {route} got error code {ret.status_code}")

if __name__ == "__main__":
    main()