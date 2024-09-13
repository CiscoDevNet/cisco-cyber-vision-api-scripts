#!/usr/bin/python3
# Cisco Cyber Vision V4.x and V5.0.x
# Vulnerability Management
# Version 1.3 - 2023-01-09
import argparse
import csv
from json import dumps

import cvconfig
import api


# TODO: Throw error if cve-id is not provided
def main():
    parser = argparse.ArgumentParser(
        prog="ack_vuln.py",
        description="Vulnerabilities Management")

    # Environment Options parsing
    parser.add_argument("--token", dest="token",
                        help="Use this token")
    parser.add_argument("--center-ip", dest="center_ip",
                        help="Specified the center FQDN or IPv4 address (default:'cybervision')")
    parser.add_argument("--center-port", dest="center_port", default=cvconfig.center_port,
                        help="Specified the center port (default: %d)" % cvconfig.center_port)

    # Main Command Parsing
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument("--export-affected-devices", dest="command_export", default=False,
                               action="store_true",
                               help="Export all affected devices into a CSV file")
    command_group.add_argument("--ack-by-preset", dest="command_ack_by_preset", default=False,
                               action="store_true",
                               help="Update all devices in this preset for given CVE ID \n")
    command_group.add_argument("--ack-by-devices", dest="command_ack_by_devices", default=False,
                               action="store_true",
                               help="Update all devices from a CSV file for given CVE ID\n")

    parser.add_argument("--cve-id", dest="cve_id", required=True,
                        help="Specified the UUID of CVE")

    parser.add_argument("--export-affected-devices-preset-name", dest="preset_name",
                        help="Preset Name, default is %s" % cvconfig.preset_name)

    parser.add_argument("--ack-by-preset-preset-name", dest="preset_name",
                        help="Preset Name, default is %s" % cvconfig.preset_name)

    parser.add_argument("--ack-comments",  dest="ack_comments",
                        help="Acknowledge comments, default is %s" % cvconfig.ack_comments)

    parser.add_argument("--filename", dest="filename", default="vulnerable_devices.csv",
                        help="Use this filename")

    parser.add_argument("--delimiter", dest="csv_delimiter",
                        help="CSV file delimiter, default is %s" % cvconfig.csv_delimiter)

    parser.add_argument("--encoding", dest="csv_encoding",
                        help="CSV file encoding, default is %s" % cvconfig.csv_encoding)

    args = parser.parse_args()

    # Handle Cyber Vision configuration
    token = set_conf(args.token, cvconfig.token)
    center_ip = set_conf(args.center_ip, cvconfig.center_ip)
    center_port = set_conf(args.center_port, cvconfig.center_port)
    csv_encoding = set_conf(args.csv_encoding, cvconfig.csv_encoding)
    csv_delimiter = set_conf(args.csv_delimiter, cvconfig.csv_delimiter)

    # Handle default values
    ack_comments = set_conf(args.ack_comments, cvconfig.ack_comments)

    if not token or not center_ip:
        print("TOKEN and CENTER_IP are mandatory, check cvconfig.py or us --token/--center-ip")

    if args.command_export:
        return export_vulnerable_devices(center_ip, center_port, token, args.filename, csv_delimiter, csv_encoding, args.cve_id, args.preset_name)
    elif args.command_ack_by_preset:
        return ack_vulnerabilities_by_preset(center_ip, center_port, token, args.cve_id, args.preset_name, ack_comments)
    elif args.command_ack_by_devices:
        return ack_vulnerabilities_by_devices(center_ip, center_port, token, args.filename, csv_delimiter, csv_encoding, args.cve_id, ack_comments)
    
    parser.print_help()


def set_conf(arg, conf):
    if arg and arg != conf:
        return arg
    return conf


def build_device_row(row, d):
    try:
        row['device-id'] = d['id']
        row['device-name'] = d['originalLabel']
        row['device-ip'] = d['ip']
        row['device-mac'] = d['mac']
        row['device-custom-name'] = d['customLabel']
        row['device-riskscore'] = d['riskScore']
        row['device-isdevice'] = d['isDevice']
    except KeyError as e:
        print("KeyError: {} for device {}".format(e, row['device-id']))
    except Exception as e:
        print(e)


def write_devices(filename, csv_encoding, csv_delimiter, devices):
    with open(filename, 'w', encoding=csv_encoding) as csvfile:
        fieldnames = ['device-id', 'device-mac', 'device-ip', 'device-name', 'device-custom-name', 'device-tags', 'device-riskscore', 'device-isdevice']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=csv_delimiter)
        writer.writeheader()
        for d in devices:
            row = {}
            build_device_row(row, d)
            writer.writerow(row)
        print(f"LOG: Exported {len(devices)} into '{filename}'")


def export_vulnerable_devices(center_ip, center_port, token, filename, csv_delimiter, csv_encoding, cve_id, preset_name):
    with api.APISession(center_ip, center_port, token) as session:

        route = f"/api/3.0/vulnerabilities?filter=cve:{cve_id}"
        cveDetails = api.get_route(session, route)
        vulnerability_ids = []
        for cveDetail in cveDetails:
            vulnerability_ids.append(cveDetail['id'])

        print(f"LOG: Found CVE {cve_id} with UUID {vulnerability_ids}")
        if not vulnerability_ids:
            print(f"ERR: CVE {cve_id} not found")
            return
        
        # hack to get all devices via 'All data' preset, should be removed later
        presets = api.get_route(session, '/api/3.0/presets')
        preset_id = 0
        if not preset_name:
            preset_name = 'All data'

        for p in presets:
            if p['label'] == preset_name:
                preset_id = p['id']
                break

        if not preset_id:
            print(f"LOG: Could not find preset id for given preset {preset_name}")
            return

        device_details = []
        for vulnerability_id in vulnerability_ids:
            route = f"/api/3.0/presets/{preset_id}/visualisations/vulnerability-list/{vulnerability_id}/devices-ids"
            devices = api.get_route(session, route)
            if devices:
                print(f"INFO: device details are being fetched....")
                for device in devices:
                    route = f"/api/3.0/devices/"+device
                    device_detail = api.get_route(session, route)
                    device_details.append(device_detail)

        # Loop to build devices
        write_devices(filename, csv_encoding, csv_delimiter, device_details)
    return


def ack_vulnerabilities_by_preset(center_ip, center_port, token, cve_id, preset_name, ack_comments):
    with api.APISession(center_ip, center_port, token) as session:
        presets = api.get_route(session, '/api/3.0/presets')
        preset_id = 0
        if not preset_name:
            preset_name = 'All data'

        for p in presets:
            if p['label'] == preset_name:
                preset_id = p['id']
                break

        if not preset_id:
            print(f"LOG: Could not find preset id for given preset {preset_name}")
            return

        route = f"/api/3.0/vulnerabilities?filter=cve:{cve_id}"
        cveDetails = api.get_route(session, route)
        vulnerability_ids = []
        for cveDetail in cveDetails:
            vulnerability_ids.append(cveDetail['id'])

        print(f"LOG: Found CVE {cve_id} with UUID {vulnerability_ids}")
        if not vulnerability_ids:
            print(f"ERR: CVE {cve_id} not found")
            return

        device_ids = []
        for vulnerability_id in vulnerability_ids:
            route = f"/api/3.0/presets/{preset_id}/visualisations/vulnerability-list/{vulnerability_id}/devices-ids"
            devices = api.get_route(session, route)
            if devices:
                device_ids.extend(devices)

        json_data = {
            "cve": cve_id,
            "deviceIds": device_ids,
            "comment": ack_comments
        }
        json_string = dumps(json_data)
        print(json_string)
        route = f"/api/3.0/vulnerability/acknowledge"
        ack_vul_response = api.put_route(session, route, json_data)
        if ack_vul_response.status_code != 200:
            print(f"RESPONSE: Calling [PUT] {route} got error code {ack_vul_response.status_code}")
    return


def ack_vulnerabilities_by_devices(center_ip, center_port, token, filename, csv_delimiter, csv_encoding, cve_id, ack_comments):
    device_ids = []
    with open(filename, 'r') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=csv_delimiter)
        for row in reader:
            device_ids.append(row["device-id"])

    json_data = {
        "cve": cve_id,
        "deviceIds": device_ids,
        "comment": ack_comments
    }

    json_string = dumps(json_data)
    print(json_string)
    with api.APISession(center_ip, center_port, token) as session:
        route = f"/api/3.0/vulnerability/acknowledge"
        ack_vul_response = api.get_route(session, route, json_data)
        if ack_vul_response.status_code != 200:
            print(f"ERROR: Calling [POST] {route} got error code {ack_vul_response.status_code}")

    return


if __name__ == "__main__":
    main()
