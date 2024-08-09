#!/usr/bin/python3
# Cisco Cyber Vision V4.0
# Group Management
import argparse
import requests
import json
import csv
import sys

import cvconfig
import api

def main():
    parser = argparse.ArgumentParser(prog="group.py",
                                     description="Group Management")
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
    
    parser.add_argument("--filename", dest="filename", help="Use this filename", default="groups.csv")
    # Main Command Parsing
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument("--export",
                               help="Export all groups into a CSV file\n",
                               action="store_true", default=False, dest="command_export")
    command_group.add_argument("--import",
                               help="Create groups from a CSV file\n",
                               action="store_true", default=False, dest="command_import")
    command_group.add_argument("--delete",
                               help="Delete all groups of the Cyber Vision center\n",
                               action="store_true", default=False, dest="command_delete")


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
        return group_export(center_ip, center_port, token, proxy, args.filename,csv_delimiter, csv_encoding)
    elif args.command_import:
        return group_import(center_ip, center_port, token, proxy, args.filename, csv_delimiter, csv_encoding)
    elif args.command_delete:
        return group_delete_all(center_ip,center_port,token, proxy)

    parser.print_help()

def set_conf(arg,conf):
    if arg and arg != conf:
        return arg
    return conf

def group_delete_all(center_ip, center_port, token, proxy):
    with api.APISession(center_ip, center_port, token, proxy) as session:
        groups = api.get_route(session, '/api/3.0/groups')
        for group in groups: 
            print(f"LOG: Deleting {group['label']}")
            ret = session.delete(f"/api/1.0/group/{group['id']}")            
            if (ret.status_code != 200):
                print(f"ERROR: Group [{group['label']}][{group['id']}] was not deleted, return code: {ret.status_code}")
        

def group_export(center_ip, center_port, token, proxy, filename,csv_delimiter, csv_encoding):
    with api.APISession(center_ip, center_port, token, proxy) as session:
        groups = api.get_route(session, '/api/3.0/groups')
        
        with open(filename, 'w', encoding=csv_encoding) as csvfile:
            fieldnames = ['group-name','group-description','group-color','group-industrial-impact']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=csv_delimiter)
            writer.writeheader()
            for g in groups:
                row = {}
                row['group-name'] = g['label']
                row['group-description'] = g['description']
                row['group-color'] = g['color']
                if 'criticalness' in g:
                    row['group-industrial-impact'] = g['criticalness']
                writer.writerow(row)
    return

def group_import(center_ip, center_port, token, proxy, filename,csv_delimiter, csv_encoding):
    with open(filename, 'r') as csvfile:
        with api.APISession(center_ip, center_port, token, proxy) as session:            
            reader = csv.DictReader(csvfile, delimiter=csv_delimiter)
            
            group_import_lib(session, reader)

def group_import_lib(session, reader):
    for row in reader:
        if not 'group-name' in row or not row['group-name']:
            continue

        print(f"LOG: Group '{row['group-name']}' - Creating...")

        industrial_impact = 0
        if 'group-industrial-impact' in row and row['group-industrial-impact']:
            industrial_impact = int(row['group-industrial-impact'])

        route = f"/api/3.0/groups"
        json = {
            "label": row['group-name'],
            "description": row['group-description'],
            "color": row['group-color'],
            "criticalness": industrial_impact,
        }
        ret = api.post_route(session, route, json)
        if ret.status_code == 409:
            print(f"LOG: Group '{row['group-name']}' - Already exists")
        elif ret.status_code != 200:
            print(f"ERROR: Calling [POST] {route} got error code {ret.status_code}")

if __name__ == "__main__":
    main()