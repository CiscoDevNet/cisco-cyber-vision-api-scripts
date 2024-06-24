#://developer.cisco.com/iot/
# See - https://github.com/CiscoDevNet/cisco-cyber-vision-api-scripts
# Behavior: Delete all groups, create groups defined in CSV, export devices, and update the
# exported device with the group using subnet info.. Then update devices. Note this is
# creating a devices CSV file that can be later modified by XLS and updated manually for corner
# case.

# Python Module
import argparse
import csv
import json
import os
import sys
import ipaddress
if sys.version_info[0] < 3 and sys.version_info[1] < 3:
    import platform
    raise Exception("Must be using above Python 3.3 - now at %s"%platform.python_version())
sys.path.insert(1, '/res')
# Cisco modules
import device
import group
import cvconfig
from res import ccv_auto_discover_networks

# Config
groups_file = "subnets.csv"
devices_file = "devices.csv"
p = 0.05
s = 1

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
    parser.add_argument("--encoding", dest="csv_encoding",
                        help="CSV file encoding, default is %s" % cvconfig.csv_encoding)
    parser.add_argument("--delimiter", dest="csv_delimiter",
                        help="CSV file delimiter, default is %s" % cvconfig.csv_delimiter)

    parser.add_argument("--filename", dest="filename", help="Use this filename", default="subnets.csv")
    # Main Command Parsing
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument("--export",
                               help="Export subnets and devices into CSV files\n",
                               action="store_true", default=False, dest="command_export")
    command_group.add_argument("--import",
                               help="push new groups from a CSV file\n",
                               action="store_true", default=False, dest="command_import")
    command_group.add_argument("--auto",
                               help="Create groups automaticcally from a CSV file\n",
                               action="store_true", default=False, dest="command_auto")


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
        ccv_auto_discover_networks.main(p , s)
        return device.device_export_group(cvconfig.center_ip, center_port, cvconfig.token, devices_file,csv_delimiter, csv_encoding)
    
    elif args.command_import:
        if not groups_file :
            print("please exectue --export to get subnets.csv file then modify it as needed and push it again via this command ")
        else:
            return manu_groupping()
  
    elif args.command_auto:
        return auto_groupping()

    parser.print_help()

def set_conf(arg,conf):
    if arg and arg != conf:
        return arg
    return conf
def manu_groupping():
    # Deleting all groups in the DB
    group.group_delete_all(cvconfig.center_ip, cvconfig.center_port, cvconfig.token)

    # Creating the groups based on CSV
    group.group_import(cvconfig.center_ip, cvconfig.center_port, cvconfig.token, groups_file,cvconfig.csv_delimiter, cvconfig.csv_encoding)

    # Updating a CSV adding Group using the subnet
    updated = 0
    with open(devices_file, 'r') as csvfile:
        devices = {}
        reader_dev = csv.DictReader(csvfile, delimiter=cvconfig.csv_delimiter)
        for dev in reader_dev:
            devices[dev['device-id']] = dev
            with open(groups_file, 'r') as csvfile:
                reader_group = csv.DictReader(csvfile, delimiter=cvconfig.csv_delimiter)
                for grp in reader_group:
                    ips = json.loads(dev['device-ip'].replace("'",'"'))
                    if ips and ipaddress.ip_address(ips[0]) in ipaddress.ip_network(grp['Subnet']):
                        devices[dev['device-id']]['group-name'] = grp["group-name"]
                        updated = updated + 1 

    print("LOG: Updated %d devices with group information based on subnet"%updated)

    new_devices_file = os.path.splitext(devices_file)[0]+"-withgrp.csv"
    with open(new_devices_file, 'w', encoding=cvconfig.csv_encoding) as csvfile:
            fieldnames = ['device-id','device-mac','device-ip','device-name','device-custom-name','device-tags','device-riskscore',
                        'group-name','group-color','group-industrial-impact',
                        'device-network','device-fw-version','device-hw-version','device-model-name','device-model-ref',                       
                        'device-riskscore-current','device-riskscore-best-achievable','device-isdevice',
                        ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=cvconfig.csv_delimiter)
            writer.writeheader()
            for id,d in devices.items():
                writer.writerow(d)
            print(f"LOG: Exported {len(devices)} into '{new_devices_file}'")

    device.device_update(cvconfig.center_ip, cvconfig.center_port, cvconfig.token, new_devices_file,cvconfig.csv_delimiter, cvconfig.csv_encoding)

def auto_groupping():

    # Deleting all groups in the DB
    group.group_delete_all(cvconfig.center_ip, cvconfig.center_port, cvconfig.token)

    #exporting subnets from center with automated group name 
    ccv_auto_discover_networks.main(p , s)

    # Creating the groups based on CSV
    group.group_import(cvconfig.center_ip, cvconfig.center_port, cvconfig.token, groups_file,cvconfig.csv_delimiter, cvconfig.csv_encoding)

    # Exporting list of devices
    device.device_export_group(cvconfig.center_ip, cvconfig.center_port, cvconfig.token, devices_file,cvconfig.csv_delimiter, cvconfig.csv_encoding)

    # Updating a CSV adding Group using the subnet
    updated = 0
    with open(devices_file, 'r') as csvfile:
        devices = {}
        reader_dev = csv.DictReader(csvfile, delimiter=cvconfig.csv_delimiter)
        for dev in reader_dev:
            devices[dev['device-id']] = dev
            with open(groups_file, 'r') as csvfile:
                reader_group = csv.DictReader(csvfile, delimiter=cvconfig.csv_delimiter)
                for grp in reader_group:
                    ips = json.loads(dev['device-ip'].replace("'",'"'))
                    if ips and ipaddress.ip_address(ips[0]) in ipaddress.ip_network(grp['Subnet']):
                        devices[dev['device-id']]['group-name'] = grp["group-name"]
                        updated = updated + 1

    print("LOG: Updated %d devices with group information based on subnet"%updated)

    new_devices_file = os.path.splitext(devices_file)[0]+"-withgrp.csv"
    with open(new_devices_file, 'w', encoding=cvconfig.csv_encoding) as csvfile:
            fieldnames = ['device-id','device-mac','device-ip','device-name','device-custom-name','device-tags','device-riskscore',
                        'group-name','group-color','group-industrial-impact',
                        'device-network','device-fw-version','device-hw-version','device-model-name','device-model-ref',                       
                        'device-riskscore-current','device-riskscore-best-achievable','device-isdevice',
                        ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=cvconfig.csv_delimiter)
            writer.writeheader()
            for id,d in devices.items():
                writer.writerow(d)
            print(f"LOG: Exported {len(devices)} into '{new_devices_file}'")

    device.device_update(cvconfig.center_ip, cvconfig.center_port, cvconfig.token, new_devices_file,cvconfig.csv_delimiter, cvconfig.csv_encoding)

if __name__ == "__main__":
    main()