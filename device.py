#!/usr/bin/python3
# Cisco Cyber Vision V4.0
# Device Management
# Version 1.3 - 2023-01-09
import argparse
from collections import defaultdict
import csv
import os
import json

import cvconfig
import api

def main():
    parser = argparse.ArgumentParser(prog="device.py",
                                     description="Device Management")
    # Options parsing
    parser.add_argument("--token", dest="token", help="Use this token")
    parser.add_argument("--center-ip", dest="center_ip",
                        help="Specified the center FQDN or IPv4 address"
                        " (default:'cybervision')")
    parser.add_argument("--center-port", dest="center_port",
                        help="Specified the center port (default: %d)"%cvconfig.center_port, 
                        default=cvconfig.center_port)
    parser.add_argument("--encoding", dest="csv_encoding",
                        help="CSV file encoding, default is %s" % cvconfig.csv_encoding)
    parser.add_argument("--delimiter", dest="csv_delimiter",
                        help="CSV file delimiter, default is %s" % cvconfig.csv_delimiter)
    
    parser.add_argument("--filename", dest="filename", help="Use this filename", default="devices.csv")
    # Main Command Parsing
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument("--export",
                               help="Export all devices into a CSV file\n",
                               action="store_true", default=False, dest="command_export")
    command_group.add_argument("--update",
                               help="Update existing groups with devices from a CSV file\n",
                               action="store_true", default=False, dest="command_update")
    command_group.add_argument("--unknown-vendors",
                               help="Get the list of unknown vendords\n",
                               action="store_true", default=False, dest="command_vendors")


    args = parser.parse_args()

    # Handle Cybervision configuration
    token = set_conf(args.token, cvconfig.token)
    center_ip = set_conf(args.center_ip, cvconfig.center_ip)
    center_port = set_conf(args.center_port, cvconfig.center_port)
    csv_encoding = set_conf(args.csv_encoding, cvconfig.csv_encoding)
    csv_delimiter = set_conf(args.csv_delimiter, cvconfig.csv_delimiter)

    if not token or not center_ip:
        print("TOKEN and CENTER_IP are mandatory, check cvconfig.py or us --token/--center-ip")

    if args.command_export:
        return device_export(center_ip, center_port, token, args.filename,csv_delimiter, csv_encoding)
    elif args.command_update:
        return device_update(center_ip, center_port, token, args.filename, csv_delimiter, csv_encoding)
    elif args.command_vendors:
        return get_unkown_vendors(center_ip, center_port, token)
    
    parser.print_help()

def set_conf(arg,conf):
    if arg and arg != conf:
        return arg
    return conf
 
def build_device_row(session,row,d):
    try:
        row['device-id'] = d['id']
        row['device-mac'] = d['mac']
        row['device-ip'] = d['ip']
        row['device-name'] = d['originalLabel']
        row['device-custom-name'] = d['customLabel']
        row['device-tags'] = "-".join(sorted(t['label'] for t in d['tags']))
        row['device-riskscore'] = d['riskScore']
        row['device-network'] = d['situation']
        row['device-isdevice'] = d['isDevice']
        # Normalized Properties
        if 'normalizedProperties' in d:
            for p in d['normalizedProperties']:
                if p['key'] == "fw-version":
                    row['device-fw-version'] = p['value']
                elif p['key'] == "hw-version":
                    row['device-hw-version'] = p['value']
                elif p['key'] == "model-name":
                    row['device-model-name'] = p['value']
                elif p['key'] == "model-ref":
                    row['device-model-ref'] = p['value']
        # Group Properties    
        if 'group' in d and d['group']:
            row['group-name'] = d['group']['label']
            row['group-color'] = d['group']['color']
            row['group-industrial-impact'] = d['group']['criticalness']
    except Exception as e: print(e)

def build_device_riskscore(session,row,d):
    # RiskScore
    if 'riskScore' in d and d['riskScore']:
        risk_score = int(d['riskScore'])
    else:
        return
    try:
        if risk_score  > 0:
            risk = api.get_route(session, f"/api/3.0/devices/{d['id']}/riskScore")
            if not risk:
                return
            row['device-riskscore-current'] = d['riskScore']
            if 'bestAchievableScore' in d:
                row['device-riskscore-best-achievable'] = d['bestAchievableScore']
            # Device Type
            if risk['deviceTypeRisk']['score'] > 0:
                row['device-riskscore-devicetype-matching'] = risk['deviceTypeRisk']['device']['deviceType']
                row['device-riskscore-devicetype-distribution'] = risk['deviceTypeRisk']['score']
                row['device-riskscore-devicetype-details'] = risk['deviceTypeRisk']['riskScoreDescription']
            # Activity
            if risk['activitiesRisk']['score'] > 0:
                row['device-riskscore-activities-matching'] = risk['activitiesRisk']['matchingTag']['label']
                row['device-riskscore-activities-distribution'] = risk['activitiesRisk']['score']
                row['device-riskscore-activities-details'] = risk['activitiesRisk']['matchingTag']['riskScoreDescription']
            # Group
            if risk['groupRisk']['score'] > 0:
                row['device-riskscore-groupimpact-matching'] = risk['groupRisk']['label']
                row['device-riskscore-groupimpact-distribution'] = risk['groupRisk']['score']
                row['device-riskscore-groupimpact-details'] = risk['groupRisk']['description']
                row['device-riskscore-groupimpact-criticalness'] = risk['groupRisk']['criticalness']
            # Vulnerabilities
            if risk['vulnerabilitiesRisk']['mostImpactingVulnerability']:
                row['device-riskscore-vulnerabilities-cve'] = risk['vulnerabilitiesRisk']['mostImpactingVulnerability']['cve']
                row['device-riskscore-vulnerabilities-distribution'] = risk['vulnerabilitiesRisk']['score']
                row['device-riskscore-vulnerabilities-details'] = risk['vulnerabilitiesRisk']['mostImpactingVulnerability']
    except Exception as e: 
        print(e)

def get_vendor_name (device):
    if 'normalizedProperties' in device:
        for p in device['normalizedProperties']:
                if p['key'] == "vendor-name":
                    return p['value']
    return ''

def get_unkown_vendors(center_ip, center_port, token):
    with api.APISession(center_ip, center_port, token) as session:
        # hack to get all devices via 'All data' preset, should be removed later
        components = api.get_route(session, '/api/3.0/components')

    unknown_vendors = {}
    for c in components:
        if c['icon'] == 'library/default.svg':
            vendor = get_vendor_name(c)
            if not vendor in unknown_vendors:
                unknown_vendors[vendor] = c['mac'][0:8]

    print(json.dumps(unknown_vendors,sort_keys=True, indent=4))
    return

def write_devices(filename,csv_encoding,csv_delimiter,devices,session):
    with open(filename, 'w', encoding=csv_encoding) as csvfile:
        fieldnames = ['device-id','device-mac','device-ip','device-name','device-custom-name','device-tags','device-riskscore',
                    'group-name','group-color','group-industrial-impact',
                    'device-network','device-fw-version','device-hw-version','device-model-name','device-model-ref',                       
                    'device-riskscore-current','device-riskscore-best-achievable','device-isdevice',
                    'device-riskscore-devicetype-matching','device-riskscore-devicetype-distribution','device-riskscore-devicetype-distribution','device-riskscore-devicetype-details',
                    'device-riskscore-activities-matching','device-riskscore-activities-distribution','device-riskscore-activities-distribution','device-riskscore-activities-details',
                    'device-riskscore-groupimpact-matching','device-riskscore-groupimpact-distribution','device-riskscore-groupimpact-distribution','device-riskscore-groupimpact-details','device-riskscore-groupimpact-criticalness',
                    'device-riskscore-vulnerabilities-cve','','device-riskscore-vulnerabilities-matching','device-riskscore-vulnerabilities-distribution','device-riskscore-vulnerabilities-details',
                    ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=csv_delimiter)
        writer.writeheader()
        for d in devices:
            row = {}
            build_device_row(session,row,d)
            build_device_riskscore(session,row,d)
            writer.writerow(row)
        print(f"LOG: Exported {len(devices)} into '{filename}'")

#
# Vulnerabiltiies
# 
def build_device_vulns(session,d):
    vulns = []
    # We are keeping vuln in a separate list
    if d['vulnerabilitiesCount'] > 0:
        try:
            if d['isDevice']:
                vulns = api.get_route(session, f"/api/3.0/devices/{d['id']}/vulnerabilities")
            else:
                vulns = api.get_route(session, f"/api/3.0/components/{d['id']}/vulnerabilities")
        except Exception as e: print(e)
    return vulns

def write_vulns(filename,csv_encoding,csv_delimiter,session,devices):
    filename_vulns = os.path.splitext(filename)[0]+"-vulns.csv"
    with open(filename_vulns, 'w', encoding=csv_encoding) as csvfile:
        fieldnames = ['device-id','device-mac','device-ip','device-name','device-custom-name',
                    'CVE','CVSS','CVSS-temporal','CVSS-vector-string','CVE-description','CVE-solution']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=csv_delimiter)
        writer.writeheader()
        
        count = 0
        for d in devices:
            vulnerabilities = build_device_vulns(session,d)
            for vuln in vulnerabilities:
                row = {}
                build_vulns_row(row,vuln,d)
                writer.writerow(row)
                count = count+1 
        print(f"LOG: Exported {count} into '{filename_vulns}'")


def build_vulns_row(row,vuln,d):
    row['device-id'] = d['id']
    row['device-mac'] = d['mac']
    row['device-ip'] = d['ip']
    row['device-name'] = d['originalLabel']
    row['device-custom-name'] = d['customLabel']
    row['CVE'] = vuln['cve']
    row['CVSS'] = vuln['CVSS']
    row['CVSS-temporal'] = vuln['CVSS_temporal']
    row['CVSS-vector-string'] = vuln['CVSS_vector_string']
    row['CVE-description'] = vuln['full_description'] + " " + vuln['summary']
    row['CVE-solution'] = vuln['solution']

#
# Credentials
#
def build_device_credentials(session,d):
    creds = []
    try:
        if d['isDevice']:
            creds = api.get_route(session, f"/api/3.0/devices/{d['id']}/credentials")
        else:
            creds = api.get_route(session, f"/api/3.0/components/{d['id']}/credentials")            
    except Exception as e: print(e)
    return creds

def write_credentials(filename,csv_encoding,csv_delimiter,session,devices):
    filename_creds = os.path.splitext(filename)[0]+"-creds.csv"
    with open(filename_creds, 'w', encoding=csv_encoding) as csvfile:
        fieldnames = ['device-id','device-mac','device-ip','device-name','device-custom-name','credential-username', 'credential-algorithm', 'credential-password', 'credential-protocol']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=csv_delimiter)
        writer.writeheader()

        count = 0
        for d in devices:
            credentials = build_device_credentials(session,d)
            for cred in credentials:
                row = {}
                build_cred_row(row,cred,d)
                writer.writerow(row)
                count = count+1 
        print(f"LOG: Exported {count} into '{filename_creds}'")
        
def build_cred_row(row,cred,d):
    row['device-id'] = d['id']
    row['device-mac'] = d['mac']
    row['device-ip'] = d['ip']
    row['device-name'] = d['originalLabel']
    row['device-custom-name'] = d['customLabel']
    row['credential-protocol'] = cred['protocol']
    if 'username' in cred: row['credential-username'] = cred['username']
    else: row['credential-username'] = "EMPTY_USERNAME"
    if 'password' in cred:
        if cred['password']:
            row['credential-password'] = cred['password']
        else:
            row['credential-password'] = "EMPTY_PASSWORD"
    else:
        row['credential-password'] = "EMPTY_PASSWORD"
    row['credential-algorithm'] = cred['algo']
    
#
# Main Functions
# 

def device_export(center_ip, center_port, token, filename,csv_delimiter, csv_encoding):
    with api.APISession(center_ip, center_port, token) as session:
        # hack to get all devices via 'All data' preset, should be removed later
        presets = api.get_route(session, '/api/3.0/presets')
        all_id = 0
        for p in presets:
            if p['label'] == 'All data':
                all_id = p['id']
                break
        route = f"/api/3.0/presets/{all_id}/visualisations/networknode-list"
        devices = api.get_route(session, route)
        
        # Loop to build devices, credentials, vulns list
        write_devices(filename,csv_encoding,csv_delimiter,devices,session)
        # If needed store vulns in another file
        write_vulns(filename,csv_encoding,csv_delimiter,session,devices)
        # If needed store credentials in another file
        write_credentials(filename,csv_encoding,csv_delimiter,session,devices)
        
    return

def device_update(center_ip, center_port, token, filename,csv_delimiter, csv_encoding):
    with open(filename, 'r') as csvfile:
        with api.APISession(center_ip, center_port, token) as session:
            # get all groups to match their name and find their ids
            route = "/api/3.0/groups"
            groups = api.get_route(session, route)
            group_dict = defaultdict()
            for g in groups:
                group_dict[g['label']] = g
            
            reader = csv.DictReader(csvfile, delimiter=csv_delimiter)
            for row in reader:
                # devices or component
                path = "devices"
                if row['device-isdevice'] == 'FALSE':
                    path = "components"

                if 'group-name' in row and row['group-name']:
                    if not row['group-name'] in group_dict:
                        print(f"ERR: Device '{row['device-name']}' -  Group '{row['group-name']}' does not exist ")
                    else:
                        print(f"LOG: Device '{row['device-name']}' - Putting in group '{row['group-name']}'")
                        group = group_dict[row['group-name']]
                        route = f"/api/3.0/groups/{group['id']}"

                        json = {
                            "op": "add",
                            "path": f"/{path}",
                            "value": [row['device-id']],
                        }
                        ret = api.patch_route(session, route, json)
                        if ret.status_code != 200:
                            print(f"ERROR: Calling [PATCH] {route} got error code {ret.status_code}")

                if 'device-custom-name' in row and row['device-custom-name']:
                    custom_name = row['device-custom-name']
                    print(f"LOG: Device '{row['device-name']}' - setting custom name '{row['device-custom-name']}'")
                    route = f"/api/3.0/{path}/{row['device-id']}/label"
                    json = {
                            "name": row['device-custom-name'],
                    }
                    ret = api.post_route(session, route, json)
                    if ret.status_code != 200:
                        print(f"ERROR: Calling [POST] {route} got error code {ret.status_code}")
    
    return

if __name__ == "__main__":
    main()
