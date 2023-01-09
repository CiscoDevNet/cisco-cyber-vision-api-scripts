"""
Cisco Cyber Vision API sample script with requests library
Test it now on the DevNet sandbox: https://devnetsandbox.cisco.com
Get the IP address of all components
"""

import requests

center_token = "ics-c2e16cedf9dd3768a17cae961dab25286adaf000-bafb27bc8fc7d49384a718a61ea8c4d94b66bc90"
center_ip = "10.10.20.53"
center_port = 443
center_base_url = "api/3.0"

def get_components_ip():
    try:
        headers = { "x-token-id": center_token }
        r_get = requests.get(f"https://{center_ip}:{center_port}/{center_base_url}/components",headers=headers,verify=False)
        r_get.raise_for_status() #if there are any request errors

        #raw JSON data response
        raw_json_data = r_get.json()

        # get only the label name and IP address of the component
        components_with_ip_and_label = {}
        for component in raw_json_data:
            components_with_ip_and_label[component["label"]] = component["ip"]

        return components_with_ip_and_label

    except Exception as e:
        return f"Error when connecting: {e}"

all_components = get_components_ip()

print(all_components)