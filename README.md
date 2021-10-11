# Cisco Cyber Vision Analyzer Rules

These rules have been created to specifically trigger on specific properties that CyberVision detects via DPI
These rules will aid in the forensic analysis when team members are reviewing network traffic

## License

This project is licensed under the Cisco Sample Code License 1.1 - see the [LICENSE.md](LICENSE.md) file for details

## API Calls

### TAGS

Get all tags
<<<<<<< HEAD
```python
GET /api/1.0/tags?token=YOUR_TOKEN_HERE
```
Get Custom tag
```python
=======
```bash
GET /api/1.0/tags?token=YOUR_TOKEN_HERE
```
Get Custom tag
```bash
>>>>>>> 57711833a6425316cd86393b0d8c3c8a80a8b223
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