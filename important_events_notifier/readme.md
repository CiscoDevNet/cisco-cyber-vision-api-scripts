# API Script to send an email alert for anomaly detection events in Cyber Vision 5.x

This directory includes an API-based script for Cyber Vision 5.x to send an email alert when Cyber Vision raises anomaly detection events.
The script is made to demonstrate Cisco Cyber Vision events filtering to raise an alert. This is an example of Python code that demonstrates how to send emails using a simple library. The code includes a username and password stored in plain text for demonstration purposes.  

Please be aware that while this example is suitable for learning or testing in a non-production environment, implementing this code in a production environment may require additional modifications to enhance security. For instance, you should consider using environment variables, secure credential storage solutions, or other best practices to protect sensitive information such as usernames and passwords.  

Always prioritize security when deploying code in a live environment.    

Before using the script, please ensure the following pre-requisites are taken care of:

1. config.ini file [Common] part -  
1.1. the API token of the Cyber Vision center needs to be changed  
1.2. if the script is not running on the center, the IP address + certificate fields need to be updated to reflect the server from which the user will execute the script.
2. config.ini file [Email] part - Modify this with the local SMTP based email server parameters.  

For example:  
```
[Email]
use_email_notifier: True  
from: <amail@gmail.com>  
to: <anothermail@cisco.com>  
host: smtp.gmail.com  
port: 587  
use_auth: True  
login:amail@gmail.com  
password:apassword  
use_tls: True  
```
Or another example:  
```
[Email]
use_email_notifier: True
from: amail@gmail.com
to: anothermail@cisco.com
host: 10.0.0.206
port: 25
use_auth: False
login:amail@gmail.com
password:apassword
use_tls: False
```

3. config.ini file [Filters] part - Modify this with the event filters you would like to use.  
3.1. filter_severities, it could have the following values: VERY_HIGH, HIGH, MEDIUM, LOW  
for example: ["HIGH", "VERY_HIGH"]  
3.2. filter_categories, it could have the following values: Anomaly Detection, Control Systems Events, Cisco Cyber Vision Operations, Extension-based alert, Cisco Cyber Vision Configuration, Signature based Detection, Cisco Cyber Vision Administration, Inventory Events, Security Events, Protocol Events  
for example: ["Security Events", "Inventory Events", "Cisco Cyber Vision Operations", "Cisco Cyber Vision Configuration"]

4. Then the script needs to be scheduled in the local OS to be launched regularly. On the center CRON could be used.  
If the script folder was added in /data/tmp the script could be launch by using the command:  
 `python3 /data/tmp/py/important_events_notifier/worker.py`  
Example to launch the script every hour at :03 (don’t forget, the system works on UTC)  
4.1. Edit crontab launching the command:  
`crontab -e` (it will edit vi editor and able you to modify the crontab file)  
4.2. Add the command bellow:  
`03 * * * * python3 /data/tmp/py/important_events_notifier/worker.py`  
Then save your cron configuration (vi command `esc` then `:wq!`)  
4.3 Check your crontab list:  
`crontab -l`  
  
  
  
  
Copyright (c) {{current_year}} Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

