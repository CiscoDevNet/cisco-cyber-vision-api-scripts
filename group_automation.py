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
import subprocess
import sys
import ipaddress
if sys.version_info[0] < 3 and sys.version_info[1] < 3:
    import platform
    raise Exception("Must be using above Python 3.3 - now at %s"%platform.python_version())
sys.path.insert(1, '/res')
# Cisco modules
import api
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
    parser.add_argument("--proxy", dest="proxy",
                        help="Specified the proxy to use (default: %s)"%cvconfig.proxy, 
                        default=cvconfig.proxy)
    parser.add_argument("--encoding", dest="csv_encoding",
                        help="CSV file encoding, default is %s" % cvconfig.csv_encoding)
    parser.add_argument("--delimiter", dest="csv_delimiter",
                        help="CSV file delimiter, default is %s" % cvconfig.csv_delimiter)

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
    proxy = set_conf(args.proxy, cvconfig.proxy)
    csv_encoding = set_conf(args.csv_encoding, cvconfig.csv_encoding)
    csv_delimiter = set_conf(args.csv_delimiter, cvconfig.csv_delimiter)

    
    if not token or not center_ip:
        print("TOKEN and CENTER_IP are mandatory, check cvconfig.py or us --token/--center-ip")

    if args.command_export:
        discover_networks(p , s, center_ip, center_port, token, proxy)
        device.device_export_group(center_ip, center_port, token, proxy, devices_file, csv_delimiter, csv_encoding)
        return
    
    elif args.command_import:
        if not os.path.isfile(groups_file) :
            print("please exectue --export to get subnets.csv file then modify it as needed and push it again via this command ")
        else:
            manu_groupping(center_ip, center_port, token, proxy, csv_delimiter, csv_encoding)
            return
  
    elif args.command_auto:
        auto_groupping(center_ip, center_port, token, proxy, csv_delimiter, csv_encoding)
        return

    parser.print_help()

def set_conf(arg,conf):
    if arg and arg != conf:
        return arg
    return conf

def discover_networks(p , s, center_ip, center_port, token, proxy):
    if p >= 1 or p <= 0:
        print("p has to be within ]0, 1[")
        quit()
    
    #data = get_data_from_db()
    data = get_data_from_api(center_ip, center_port, token, proxy)
    wellconf, notwellconf = ccv_auto_discover_networks.compute_subnets(data, p, s)

    ccv_auto_discover_networks.write_subnets(wellconf, notwellconf)

# must return a dictionary keyed by sensor id containing lists of ip pairs
# like { "sensor_id": [(ip1,ip2), (ip1,ip3)] }
def get_data_from_db():
    print("LOG: Fetching data from DB")
    result = {}

    sensor_list_cmd = "sbs db exec \"select serial_number, id from sensor;\""
    sensor_list_bytes = subprocess.check_output(sensor_list_cmd, shell=True)
    sensor_list = sensor_list_bytes.decode()

    for line in sensor_list.splitlines():
        sensor_id = line.split("|")[1]

        result[sensor_id] = []

        ip_pairs_cmd = "sbs db exec \"select ca.ip as ip_a, cb.ip as ip_b from activity a left join activity_tag at on a.id = at.activity_id left join component ca on ca.id = a.cmp_a_component_id left join component cb on cb.id = a.cmp_b_component_id where a.sensor_id = '"+sensor_id+"' and at.tag_id ='ARP' and ca.ip is not NULL and ca.mac != 'ff:ff:ff:ff:ff:ff' and cb.ip is not NULL and cb.mac != 'ff:ff:ff:ff:ff:ff';\""
        
        ip_pairs_bytes = subprocess.check_output(ip_pairs_cmd, shell=True)
        ip_pairs = ip_pairs_bytes.decode()

        for line in ip_pairs.splitlines():
            ips = line.split("|")

            result[sensor_id].append(ips)

    return result

def get_data_from_api(center_ip, center_port, token, proxy):
    # from api we don't have sensor info, should not be a problem
    print("LOG: Fetching data from API")
    result = {"all_sensor": []}

    with api.APISession(center_ip, center_port, token, proxy) as session:
        activities = api.get_route(session, '/api/3.0/activities')

        for act in activities:
            arp = False
            for tag in act["tags"]:
                if tag["id"] == "ARP":
                    arp = True
                    break
            if not arp or not "ip" in act["left"] or not "ip" in act["right"] or \
                int(act["left"]["mac"][0:2], 16) & 1 or int(act["right"]["mac"][0:2], 16) & 1:
                continue

            
            ipA = act["left"]["ip"]
            ipB = act["right"]["ip"]

            result["all_sensor"].append([ipA, ipB])
    return result


def manu_groupping(center_ip, center_port, token, proxy, csv_delimiter, csv_encoding):
    # Deleting all groups in the DB
    group.group_delete_all(center_ip, center_port, token, proxy)

    # Creating the groups based on CSV
    group.group_import(center_ip, center_port, token, proxy, groups_file, csv_delimiter, csv_encoding)

    # Updating a CSV adding Group using the subnet
    updated = 0
    with open(devices_file, 'r') as csvfile:
        devices = {}
        reader_dev = csv.DictReader(csvfile, delimiter=cvconfig.csv_delimiter)
        for dev in reader_dev:
            devices[dev['device-id']] = dev
            ips = json.loads(dev['device-ip'].replace("'",'"'))
            with open(groups_file, 'r') as csvfile:
                reader_group = csv.DictReader(csvfile, delimiter=cvconfig.csv_delimiter)
                for grp in reader_group:
                    for ip in ips:
                        if ipaddress.ip_address(ip) in ipaddress.ip_network(grp['Subnet']):
                            devices[dev['device-id']]['group-name'] = grp["group-name"]
                            updated = updated + 1 
                            break
                    else:
                        continue
                    break

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

    device.device_update(center_ip, center_port, token, proxy, new_devices_file, csv_delimiter, csv_encoding)

def auto_groupping(center_ip, center_port, token, proxy, csv_delimiter, csv_encoding):

    # Deleting all groups in the DB
    group.group_delete_all(center_ip, center_port, token, proxy)

    #exporting subnets from center with automated group name 
    discover_networks(p , s, center_ip, center_port, token, proxy)

    # Creating the groups based on CSV
    group.group_import(center_ip, center_port, token, proxy, groups_file, csv_delimiter, csv_encoding)

    # Exporting list of devices
    device.device_export_group(center_ip, center_port, token, proxy, devices_file, csv_delimiter, csv_encoding)

    # Updating a CSV adding Group using the subnet
    updated = 0
    with open(devices_file, 'r') as csvfile:
        devices = {}
        reader_dev = csv.DictReader(csvfile, delimiter=csv_delimiter)
        for dev in reader_dev:
            devices[dev['device-id']] = dev
            ips = json.loads(dev['device-ip'].replace("'",'"'))
            with open(groups_file, 'r') as csvfile:
                reader_group = csv.DictReader(csvfile, delimiter=csv_delimiter)
                for grp in reader_group:
                    for ip in ips:
                        if ips and ipaddress.ip_address(ip) in ipaddress.ip_network(grp['Subnet']):
                            devices[dev['device-id']]['group-name'] = grp["group-name"]
                            updated = updated + 1
                            break
                    else:
                        continue
                    break

    print("LOG: Updated %d devices with group information based on subnet"%updated)

    new_devices_file = os.path.splitext(devices_file)[0]+"-withgrp.csv"
    with open(new_devices_file, 'w', encoding=csv_encoding) as csvfile:
            fieldnames = ['device-id','device-mac','device-ip','device-name','device-custom-name','device-tags','device-riskscore',
                        'group-name','group-color','group-industrial-impact',
                        'device-network','device-fw-version','device-hw-version','device-model-name','device-model-ref',                       
                        'device-riskscore-current','device-riskscore-best-achievable','device-isdevice',
                        ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=csv_delimiter)
            writer.writeheader()
            for id,d in devices.items():
                writer.writerow(d)
            print(f"LOG: Exported {len(devices)} into '{new_devices_file}'")

    device.device_update(center_ip, center_port, token, proxy, new_devices_file, csv_delimiter, csv_encoding)

if __name__ == "__main__":
    main()