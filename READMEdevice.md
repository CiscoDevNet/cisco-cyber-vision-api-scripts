## API Pack for Cyber Vision 4.0

This directory includes several API based scripts for Cyber Vision 4.0

It includes:
 - device.py: export devices to a CSV file ; update devices group and custom name based on the CSV data ; export list of vulnerabilities ; export list of credentials
 - group.py: export groups to a CSV file ; update groups based on the CSV data
 - preset.py: export custom presets to a CSV file ; (update is non working for the moment)
 - property.py: export flows based on start,end date or tag, extract a property and build a baseline. Can check later if another period of time contains the same property value. Example: DNS Baseline - are the DNS request saved for a week, the same the week after. Notice: counts are just provided for visibility, no check on the volume

All scripts are using the API v3

 Nota Bene: device.py / group.py are made to be replacement for the cmdb.py script from 2017 (4 years old). First, they are expecting the user to define the groups and create them as first step. Then in a second step they can use device.py to update the groups of the device. Secondly, as the device are made of several components with various addresses, the device are updated using their ID. So the initial CSV file must be first built using a CSV export and then use device.py to update the devices.
