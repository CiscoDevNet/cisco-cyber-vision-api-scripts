# Cisco Cyber Vision Analyzer Rules

These rules have been created to specifically trigger on specific properties that CyberVision detects via DPI
These rules will aid in the forensic analysis when team members are reviewing network traffic

### Details
Analyzer Rules are built out in two stages.
1. Create Tag
2. Find Property Value
3. Build Property Analyzer Rule

You need to have a TAG value created to assign to Property Analyzer Rule

## License

This project is licensed under the Cisco Sample Code License 1.1 - see the [LICENSE.md](LICENSE.md) file for details

## API Calls

### TAGS

These are the standard API calls for TAGS with API Version 1.0
It Covers the basics needed to create the core of the Analyzer rules.

Get all tags
```python
GET /api/1.0/tags?token=YOUR_TOKEN_HERE
```
Get Custom tag
```python
GET /api/1.0/tags?token=YOUR_TOKEN_HERE
```
Get Custom tag
```python
GET /api/1.0/analyzer/tag/{custom tag}?token=YOUR_TOKEN_HERE
```
Create a tag
```python
POST /api/1.0/analyzer/tag?token=YOUR_TOKEN_HERE
{
    "tag": TAG_KEY,
    "label": TAG_NAME,
    "desc": TAG_DESCRIPTION
    "type": TAG_TYPE
    "IT": TAG_DOMAIN
    "OT": TAG_DOMAIN
}
```

### ANALYZER RULES

Get all analyzer rules
```python
GET /api/1.0/analyzer/property/rule/?token=YOUR_TOKEN_HERE
```

Get custom rule
```python
GET /api/1.0/analyzer/property/rule/{id}?token=YOUR_TOKEN_HERE
```

Creat a custom property analyzer rule
```python
POST /api/1.0/analyzer/property/rule/?token=YOUR_TOKEN_HERE
{
"test": {
        "operator": OPERATOR_TYPE,
        "conditions": [{
			"name": CONDITION_TYPE,
			"params": {
    			PARAMETERS_LIST
			}
		}]
},
"actions": [{
    "name": ACTION_TYPE,
    "params": {
  	 	PARAMETERS_LIST
  	 }
}]
}
```

Delete a custom property analyzer rule
```python
DELETE /api/1.0/analyzer/property/rule/{id}?token=YOUR_TOKEN_HERE
```

## Script JSON Design

### TAG JSON Design

As we can see above the TAG POST Rule contains the following fields:
```python
{
    "tag": TAG_KEY,
    "label": TAG_NAME,
    "desc": TAG_DESCRIPTION
    "type": TAG_TYPE
    "IT": TAG_DOMAIN
    "OT": TAG_DOMAIN
}
```
What we have done below is created a list that contains the required elements:
- TAG_KEY - This is the Key that will be used to reference the newly created tag
- TAG_NAME - This is the human readable tag that is assigned in the User Interface
- TAG_DESCRIPTION - This description shows up under the component section
- TAG_IMPORTANCE - This determines whether it is RED or not

```python
#("TAG","LABEL","DESCRIPTION","IMPORTANT")
tag_list = [
    ("GOBUSTER","GObuster Tool","Directory/File and DNS busting tool written in Go","true"),
]
```

### ANALYZER JSON Design

As we can see above the ANALYZER POST Rule contains the following fields:
```python
POST /api/1.0/analyzer/property/rule/?token=YOUR_TOKEN_HERE
{
"test": {
        "operator": OPERATOR_TYPE,
        "conditions": [{
            "name": CONDITION_TYPE,
            "params": {
                PARAMETERS_LIST
            }
        }]
},
"actions": [{
    "name": ACTION_TYPE,
    "params": {
        PARAMETERS_LIST
     }
}]
}
```
What we have done below is created a list that contains the required elements:
- Conditions PARAMETERS_LIST (Property:Value) - This is the key pair that needs to be discovered/determined from analyzing the traffic
- Actions PARAMETERS_LIST (TAG_KEY) - This is what we built in the previous step

There are more elements that can be set as shown below in this example:
```python
#("PROPERTY","IDENTIFIER","TAG")
rule_list = [
    ("http-user-agent",".gobuster","GOBUSTER"),
]
```

```python
payload = '{ \
            "test":{ \
                "operator":"or", \
                "conditions": [{ \
                    "name":"PropValue", \
                    "params": { \
                        "property":"%s", \
                        "value":"%s"}}]}, \
            "actions": [{ \
                "name":"TagFlow", \
                "params": { \
                    "tag":"%s", \
                    "type":"important", \
                    "throw_admin_event": true}}]}' % (i[0],i[1],i[2])
```

