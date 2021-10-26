# Cisco Cyber Vision API Scripts

This directory includes several API based scripts for Cyber Vision 4.0

It includes:
 - device.py: export devices to a CSV file ; update devices group and custom name based on the CSV data ; export list of vulnerabilities ; export list of credentials
 - group.py: export groups to a CSV file ; update groups based on the CSV data
 - preset.py: export custom presets to a CSV file ; (update is non working for the moment)
 - property.py: export flows based on start,end date or tag, extract a property and build a baseline. Can check later if another period of time contains the same property value. Example: DNS Baseline - are the DNS request saved for a week, the same the week after. Notice: counts are just provided for visibility, no check on the volume

All scripts are using the API v3

 Nota Bene: device.py / group.py are made to be replacement for the cmdb.py script from 2017 (4 years old). First, they are expecting the user to define the groups and create them as first step. Then in a second step they can use device.py to update the groups of the device. Secondly, as the device are made of several components with various addresses, the device are updated using their ID. So the initial CSV file must be first built using a CSV export and then use device.py to update the devices.


1. cvconfig.py file [Common] part -  

1.1. the API token of the Cyber Vision center needs to be changed  
1.2. if the script is not running on the center, the IP address + certificate fields need to be updated to reflect the server from which the user will execute the script.

In order to add devices to the groups, please follow these steps :

2. Add groups 

Groups can be added manually or using the group.py script 

2.1 use group.py with export option to get the csv file
2.2 Add needed groups to the CSV file then use the import option of group.py scrypt

3. Add devices to a group

3.1 Export device list using the option export of the device.py script
3.2 Update devices group on the .csv file generated and use update option with the modified file so devices will be added to groups

4. Update custom name on Devices

4.1 Export device list using the option export of the device.py script
4.2 On the generated file update the custom name and use update option of device.py scrypt to upload the updated file


## License

This project is licensed under the Cisco Sample Code License 1.1 - see the [LICENSE.md](LICENSE.md) file for details

## Further Links

* [Cisco DevNet Website](https://developer.cisco.com)
