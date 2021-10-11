import requests

# Note that there is no validation created for these imputs
ip_addr =  input("Enter IP Address: ")
token = input("Enter API Token: ")

## Static Inputs
#headers = {
#  'x-token-id': 'ics-ccb4840411f25459b1a15c65df7d512c3811b76f-759766b65578ceb34d7853c71e6b1815a3293f6d',
#  'Content-Type': 'text/plain'
#}

# Add TAG
#urlT = "https://192.168.195.130/api/1.0/analyzer/tag?"

# Add RULE
#urlR = "https://192.168.195.130/api/1.0/analyzer/property/rule/"


# Dynamic Inputs
headers = {
	'x-token-id': token,
	'Content-Type': 'text/plain'
}

urlT = "https://"+ip_addr+"/api/1.0/analyzer/tag?"
urlR = "https://"+ip_addr+"/api/1.0/analyzer/property/rule/"



#("TAG","LABEL","DESCRIPTION","IMPORTANT")
tag_list = [
	("GOBUSTER","GObuster Tool","Directory/File and DNS busting tool written in Go","true"),
	("DIRBUSTER","Dirbuster Tool","Directory/File and DNS busting tool","true"),
	("ZAP","Zap Tool","Directory/File and DNS busting tool","true"),
	("WFUZZ","WFuzz Tool","Directory/File and DNS busting tool","true"),
	("DIRB_BIG","Dirb_big Wordlist","Dirb Big.txt wordlist","true"),
	("DIRB_COMMON","Dirb_common Wordlist","Dirb Common.txt wordlist","true"),
	("NIKTO","Nikto Tool","Enumeration Tool","true"),
	("NMAP","Nmap Tool","Enumeration Tool","true"),
	("HYDRA","Hydra Tool","Password Bruteforce Tool","true"),
	("SFISH","SFish Tool","Enumeration Tool","true"),
	("CADAVER","Cadaver Tool","Web Authoring Tool","true"),
	("DAVTEST","DavTest Tool","Web Authoring Tool","true"),
	("WHATWEB","WhatWeb Tool","Enumeration Tool","true"),
	("COMMIX","Commix Tool","Enumeration Tool","true"),
	("CURL","Curl Tool","Web Query Tool","true"),
	("METASPLOIT","Metasploit Tool","Metasploit Tool","true"),
	("ENUM4LINUX","Enum4linux Tool","Enumlinux Tool","true"),
	("MIMIKATZ","Mimikatz Tool","Mimikatz Tool","true"),
	("WINPEAS","WinPeas Tool","WinPeas Tool","true"),
	("SHERLOCK","Sherlock Tool","Sherlock Tool","true"),
	("PSEXESVC","PSEXEC Service","PSEXESVC Tool","true"),
	("FILE_HTA","HTA Transfer","HTA File Detected","true"),
	("FILE_PDF","PDF Transfer","PDF File Detected","true"),
	("FILE_EXE","EXE Transfer","EXE File Detected","true"),
	("FILE_ASP","ASP Transfer","ASP File Detected","true"),
	("FILE_ASPX","ASPX Transfer","ASPX File Detected","true"),
	("FILE_CFM","CFM Transfer","CFM File Detected","true"),
	("FILE_JSP","JSP Transfer","JSP File Detected","true"),
	("FILE_CGI","CGI Transfer","CGI File Detected","true"),
	("FILE_PL","PL Transfer","PL File Detected","true"),
	("FILE_PHP","PHP Transfer","PHP File Detected","true"),
	("FILE_C","C Transfer","C File Detected","true"),
]

for i in tag_list:
	payload = '{"tag":"%s","label":"%s","desc":"%s","important": %s}' % (i[0],i[1],i[2],i[3]) 
	response = requests.request("POST", urlT, headers=headers, data=payload, verify=False)
	print(response.text)



#("PROPERTY","IDENTIFIER","TAG")
rule_list = [
	("http-user-agent",".gobuster","GOBUSTER"),
	("http-url","/!res","DIRB_BIG"),
	("http-url","/_net","DIRB_COMMON"),
	("http-user-agent",".DirBuster","DIRBUSTER"),
	("http-user-agent",".Nikto","NIKTO"),
	("http-user-agent",".Nmap","NMAP"),
	("http-user-agent",".Hydra","HYDRA"),
	("http-user-agent","sfish.","SFISH"),
	("http-user-agent","cadaver.","CADAVER"),
	("http-user-agent","DAV.","DAVTEST"),
	("http-user-agent","WhatWeb.","WHATWEB"),
	("http-user-agent","commix.","COMMIX"),
	("http-user-agent",".ZAP","ZAP"),
	("http-user-agent","Wfuzz.","WFUZZ"),
	("http-user-agent","curl.","CURL"),
	("http-url","/0day/","METASPLOIT"),
	("smb-dialect-proposed","2.0.2,2.1,unknown0.2.2,unknown0.2.4,3.0,3.0.2,unknown0.1.0,3.1.1","ENUM4LINUX"),
	("http-url",".mimikatz","MIMIKATZ"),
	("http-url","winPEAS.exe","WINPEAS"),
	("http-url","Sherlock.ps1","SHERLOCK"),
	("smb-pipe-name",".PSEXESVC","PSEXESVC"),
	("http-content-type","application/pdf","FILE_PDF"),
	("http-content-type","application/hta","FILE_HTA"),
	("http-url",".exe","FILE_EXE"),
	("http-url",".asp","FILE_ASP"),
	("http-url",".aspx","FILE_ASPX"),
	("http-url",".cfm","FILE_CFM"),
	("http-url",".jsp","FILE_JSP"),
	("http-url",".cgi","FILE_CGI"),
	("http-url",".pl","FILE_PL"),
	("http-url",".php","FILE_PHP"),
	("http-url",".c","FILE_C"),
]

for i in rule_list:
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
	response = requests.request("POST", urlR, headers=headers, data=payload, verify=False)
	print(response.text)




