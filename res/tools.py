import csv
import ipaddress
from tempfile import NamedTemporaryFile
import shutil

# Replace 'yourfile.csv' with the path to your CSV file
csv_file_path = 'subnets.csv'
temp_file_path = 'temp_subnets.csv'

# Function to check if two IP networks overlap
def are_ips_on_same_network(ip1, ip2):
    return ip1.overlaps(ip2)

# Function to remove the smallest subnet
def remove_smallest_subnet(ip1, ip2):
    if ip1.prefixlen < ip2.prefixlen:
        return ip2
    else:
        return ip1
    
def removeduplicateline() :
    # Dictionary to keep track of unique values in the first column
    unique_values = {}

    # Read the CSV file and write to a temporary file with duplicates removed
    with open(csv_file_path, mode='r', newline='') as infile, \
        open(temp_file_path, mode='w', newline='') as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        for row in reader:
            # Check if the first column value is already in the dictionary
            if row[0] not in unique_values:
                # Write the row to the output file
                writer.writerow(row)
                # Mark the value as seen
                unique_values[row[0]] = None

    # Replace the original CSV file with the temporary file
    import os
    os.replace(temp_file_path, csv_file_path)

    print(f"LOG: Exported Network list into '{csv_file_path}'")


def compare_networks():

        
    # Read IP addresses from CSV and process them
    ip_networks = []

    # Open the CSV file and read the IP addresses
    with open(csv_file_path, mode='r') as file:
        reader = csv.reader(file)
        # Skip the first line (header)
        next(reader, None)  # Advance to the next line    
        for row in reader:
            # Assuming the IP address with subnet is in the first column
            ip = ipaddress.ip_network(row[0], strict=False)
            ip_networks.append(ip)

    # Compare each IP address with each other to find out if they are on the same network
    for i in range(len(ip_networks)):
        for j in range(i+1, len(ip_networks)):
            if are_ips_on_same_network(ip_networks[i], ip_networks[j]):
                # Remove the smallest subnet
                smaller_subnet = remove_smallest_subnet(ip_networks[i], ip_networks[j])
                ip_networks.remove(smaller_subnet)
                break
    sorted_networks = sorted(ip_networks, key=lambda net: net.prefixlen, reverse=False)           
    # Write the result back to a new CSV file
    with open('filtered_ip_addresses.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        for ip in sorted_networks:
            writer.writerow([str(ip)])
    
    print('Filtered IP addresses have been saved to "filtered_ip_addresses.csv"')


