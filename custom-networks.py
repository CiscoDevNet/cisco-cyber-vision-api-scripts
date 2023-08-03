#!/usr/bin/python3
# Cisco Cyber Vision V4.0
# Network Management
# Version 1.0 - 2023-08-03
import csv
import argparse
import json
import io
import cvconfig
import api
import sys


def main():
    parser = argparse.ArgumentParser(prog="custom_networks.py",
                                     description="Custom Network Management")
    # Options parsing
    parser.add_argument("--token", dest="token", help="Use this token")
    parser.add_argument("--center-ip", dest="center_ip",
                        help="Specified the center FQDN or IPv4 address"
                             " (default:'cybervision')")
    parser.add_argument("--center-port", dest="center_port",
                        help="Specified the center port (default: %d)" % cvconfig.center_port,
                        default=cvconfig.center_port)
    parser.add_argument("--encoding", dest="csv_encoding",
                        help="CSV file encoding, default is %s" % cvconfig.csv_encoding)
    parser.add_argument("--delimiter", dest="csv_delimiter",
                        help="CSV file delimiter, default is %s" % cvconfig.csv_delimiter)
    parser.add_argument("--filename", dest="filename", help="Use this filename, default is custom-networks.csv",
                        default="custom-networks.csv")
    # Main Command Parsing
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument("--import",
                               help="Create custom networks from a CSV file\n",
                               action="store_true", default=False, dest="create")

    command_group.add_argument("--export",
                               help="Export all cusrom networks into a CSV file\n",
                               action="store_true", default=False, dest="command_export")
    command_group.add_argument("--delete",
                               help="Delete all custom networks",
                               action="store_true", default=False, dest="delete")

    args = parser.parse_args()

    # Handle Cybervision configuration
    token = set_conf(args.token, cvconfig.token)
    center_ip = set_conf(args.center_ip, cvconfig.center_ip)
    center_port = set_conf(args.center_port, cvconfig.center_port)
    csv_encoding = set_conf(args.csv_encoding, cvconfig.csv_encoding)
    csv_delimiter = set_conf(args.csv_delimiter, cvconfig.csv_delimiter)

    if not token or not center_ip:
        print("TOKEN and CENTER_IP are mandatory, check cvconfig.py or us --token/--center-ip")

    if args.token:
        token = args.token
    if args.center_ip:
        center_ip = args.center_ip
    if args.filename:
        csv_file = args.filename
    if not token or not center_ip:
        print("TOKEN and CENTER_IP are mandatory, check config.py or use --token/--center-ip")

    if args.create:
        if not csv_file:
            print("Missing required parameter: --csv-file path_to_csv_file")
            print_csv_file_format()
            return
        create_networks(center_ip=center_ip, center_port=center_port, token=token, csv_file=csv_file,
                        csv_delimiter=csv_delimiter)
        return
    if args.delete:
        delete_networks(center_ip=center_ip, center_port=center_port, token=token)
        return
    if args.command_export:
        response = get_network_data(center_ip=center_ip, center_port=center_port, token=token)
        csv_data = convert_json_to_csv(response, csv_delimiter=csv_delimiter)

        with open(csv_file, "w", encoding=csv_encoding) as file:
            file.write(csv_data)
        print(csv_data)
        return
    parser.print_help()


def print_csv_file_format():
    print("Valid CSV file format example")
    print("name,type,ip_range,vlan_id,duplicated,split_devices_per_sensor")
    print("Network3,IT Internal,172.16.0.0/16,2003,False,True")
    print("Network2,IT Internal,192.168.1.0/24,1001,True,False")
    print("Note: In case name has a comma, then, provide the name in double quotes")


def create_networks(center_ip, center_port, token, csv_file, csv_delimiter):
    networks = read_csv_file(csv_file, csv_delimiter)
    if networks:
        with api.APISession(center_ip, center_port, token) as session:
            response = api.post_route(session, '/api/3.0/networks/', json=networks)
            if response.status_code != 200:
                print_response(response)
                print('ERROR: Failed to create custom networks')
            else:
                print_response(response)
                print('INFO: Successfully created custom networks')
    else:
        print("INFO: CSV file is empty")


def delete_networks(center_ip, center_port, token):
    network_data = get_network_data(center_ip=center_ip, center_port=center_port, token=token)
    if network_data:
        custom_network_ids = [entry["id"] for entry in network_data]
        with api.APISession(center_ip, center_port, token) as session:
            response = api.delete_route(session, '/api/3.0/networks', json=custom_network_ids)
            if response.status_code != 200:
                print_response(response)
                print('ERROR: Failed to delete custom networks')
            else:
                print_response(response)
                print('INFO: Successfully deleted custom networks')
    else:
        print('INFO: Nothing to delete')


def get_network_data(center_ip, center_port, token):
    with api.APISession(center_ip, center_port, token) as session:
        return api.get_route(session, '/api/3.0/networks')


def read_csv_file(csv_file, csv_delimiter):
    networks = []
    try:
        with open(csv_file, newline='') as csvfile:
            reader = csv.DictReader(csvfile, delimiter=csv_delimiter)
            for row in reader:
                vlan_id = int(row['vlan_id']) if row['vlan_id'].strip() else None
                network = {
                    "name": row['name'],
                    "type": row['type'],
                    "ipRange": row['ip_range'],
                    "vlanId": vlan_id,
                    "duplicated": row['duplicated'].lower() == 'true',
                    "splitDevicesPerSensor": row['split_devices_per_sensor'].lower() == 'true'
                }

                networks.append(network)
    except FileNotFoundError:
        print("Error: File '{csv_file}' not found.")
        sys.exit(1)
    except BaseException as ex:
        print("Error: File '{csv_file}' is not well formatted.")
        print(ex)
        print_csv_file_format()
        sys.exit(1)
    return networks


def print_response(response):
    print(f'Response Status :{response.status_code}')
    try:
        print(f'Response Body: {json.dumps(response.json(), indent=2)}')
    except BaseException:
        print(f'Response Body: {response.content.decode()}')


def convert_json_to_csv(json_data, csv_delimiter):
    csv_output = io.StringIO()
    # name,type,ip_range,vlan_id,duplicated,split_devices_per_sensor
    fieldnames = ['id', 'name', 'type', 'ipRange',
                  'vlanId', 'duplicated', 'splitDevicesPerSensor']
    headers = ['id', 'name', 'type', 'ip_range', 'vlan_id', 'duplicated', 'split_devices_per_sensor']
    writer = csv.DictWriter(csv_output, fieldnames=fieldnames, delimiter=csv_delimiter)
    writer.writerow(dict(zip(fieldnames, headers)))
    writer.writerows(json_data)
    csv_output.seek(0)
    return csv_output.getvalue()


def set_conf(arg, conf):
    if arg and arg != conf:
        return arg
    return conf


if __name__ == "__main__":
    main()
