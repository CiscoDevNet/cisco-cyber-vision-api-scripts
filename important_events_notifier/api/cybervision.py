#!/usr/bin/python3
#
# Sentryo.net - CyberVision API library
# developers@sentryo.net
#
import datetime
import requests
import re
import json
import ssl
import sys
import urllib.request
import urllib.parse
import requests
import ipaddress
requests.packages.urllib3.disable_warnings()  # pylint: disable=locally-disabled,no-member

# Components API
def get_all_components(token, center_ip, extras=[]):
    return get_all(token, center_ip, extras)

# First function to get all component
# return a pruned list of component with some properties
def get_all(token, center_ip, extras=[]):
    # request
    route = '/api/1.0/component'
    results = call_route_recursive(route, token, center_ip)

    components = {}
    for r in results:
        c = {}
        try:
            if 'name' in r:
                c['Name'] = r['name']
            if 'mac' in r:
                c['Mac'] = r['mac']
            if 'ip' in r:
                c['IP'] = r['ip']
            if 'group' in r:
                c['Group Name'] = r['group']
            if 'custom_name' in r:
                c['Custom Name'] = r['custom_name']
            if 'tags' in r:
                c['Tags'] = r['tags']

            for p in extras:
                if p in r['properties']:
                    c[p] = r['properties'][p]
        except:
            print("ERROR: get_all '%s'" % r)

        components[r['id']] = c

    return components


def get_all_component(token, center_ip):
    # request
    route = '/api/1.0/component'
    return call_route_recursive(route, token, center_ip)

# Vulnerability
def get_vulnerabilities(token, center_ip, cid):
    route = '/api/3.0/components/%s/vulnerabilities' % cid
    return call_route(route, {}, token, center_ip)

def get_all_vulnerabilities(token, center_ip, components):
    vulnerabilities = {}
    for c in components:
        vulns = get_vulnerabilities(token, center_ip, c['id'])
        # Adding the list of vulns to the component
        if vulns:
            c['vulnerabilities'] = vulns
            # Building the cross reference between vuln and component
            for v in vulns:
                vid = v['cve']
                if not vid in vulnerabilities:
                    vulnerabilities[vid] = []
                vulnerabilities[vid].append(c['id'])
    print("LOG: Found %d vulnerabilities accross %d components"%(len(vulnerabilities),len(components)))
    return vulnerabilities

# Search for vulnerabilities
def search_vulnerabilities(components,vulnerabilities,networks=[], groups=[],cves=[],component_tags=[]):
    comps = []
    rets = []
    # find components that match the vulnerabilities
    if cves:
        for cve in cves:
            for v in vulnerabilities:
                if v == cve:
                    comps.extend(vulnerabilities[v])
        # DEBUG
        # print("Matching CVE: " + ','.join(comps))
    
    # find component that match networks the parameters
    for c in components:
        # does not match vulns 
        if c['id'] not in comps:
            continue
        if networks:
            match_net = False
            ip = ipaddress.ip_address(c['ip'])
            for n in networks:
                net = ipaddress.ip_network(n)
                if ip in net:
                    match_net = True
            if match_net == False:
                continue            
        if groups and 'group' in c:
            if c['group'] not in groups:
                continue
        if component_tags:
            match_tag = False
            for t in c['tags']:
                if t in component_tags:
                    match_tag = True
            if match_tag == False:
                continue
        rets.append(c)
    return rets

def get_all_activities(token, center_ip):
    route = "/api/3.0/presets"
    presets = call_route(route, {}, token, center_ip)
    alldata_id = ''
    for p in presets:
        if p['label'] == 'All data':
            alldata_id = p['id']

    route = "/api/3.0/presets/%s/visualisations/activity-list" % alldata_id
    return call_route(route, {}, token, center_ip)

# Flow API
def get_all_flows(token, center_ip, max_element=None, stats=False, debug=False, params=None):
    route = '/api/1.0/flows'
    # DEBUG: switch the two lines
    result = call_route_recursive(
        route, token, center_ip, debug, max_element, params)
    #result = call_route(route,{'limit':1000},token,center_ip)
    if len(result) == 0:
        print("ERROR: Unable to get all flows")
        return
    else:
        print("LOG: Now reformating and gathering stats for %d elements" %
              (len(result)))

    # DNS TLD extraction
    dns_extractor_1 = re.compile(
        r'([A-Z0-9.-]+\.)?([A-Z0-9.-]+\.[A-Z]{2,4})', re.I)
    dns_extractor_2 = re.compile(
        r'([A-Z0-9.-]+\.)?([A-Z0-9.-]+\.[A-Z0-9.-]+\.[A-Z]{2,4})', re.I)

    # Loop over all the flows, grab their stats and
    # merge the stats list with the flow dict
    for r in result:
        if 'ip' in r['src']:
            r['src-ip'] = r['src']['ip']
        if 'port' in r['src']:
            r['src-port'] = r['src']['port']
        r['src-mac'] = r['src']['mac']
        r['src-id'] = r['src']['component']['id']

        if 'ip' in r['dst']:
            r['dst-ip'] = r['dst']['ip']
        if 'port' in r['dst']:
            r['dst-port'] = r['dst']['port']
        r['dst-mac'] = r['dst']['mac']
        r['dst-id'] = r['dst']['component']['id']

        r.pop('src', None)
        r.pop('dst', None)

        if 'tags' in r:
            nt = []
            for t in r['tags']:
                nt.append(t)
            r['tags'] = nt

        r['dnsquestion'] = ''
        r['dnstld'] = ''
        if 'properties' in r:

            for key, val in r['properties'].items():
                # Extract VLAN-ID
                if key == 'vlan-id':
                    r['vlan-id'] = val

                # Extract HTTP URL:
                if key == 'http-url':
                    r['http-url'] = val

                # Extract DNS Properties and store them
                # TODO move to a list as it could have multiple request per flow ?
                if key == 'dns-question':
                    # Store DNS question
                    r['dnsquestion'] = val
                    # Extract DNS TLD
                    match = dns_extractor_1.match(val)
                    if match and match.group(2)[:4] == 'com.':
                        match = dns_extractor_2.match(val)
                    if match:
                        r['dnstld'] = match.group(2)

        # option: get stats for all the flows
        if stats == False:
            continue

        n = {}
        for l in get_flow_stats(r['id'], token, center_ip):
            if l['direction'] == 'Client→Server':
                n['c2s_packets'] = l['nb_packets']
                if 'l2_bytes' in l:
                    n['c2s_l2_bytes'] = l['l2_bytes']
                if 'l7_bytes' in l:
                    n['c2s_l7_bytes'] = l['l7_bytes']
            if l['direction'] == 'Server→Client':
                n['s2c_packets'] = l['nb_packets']
                if 'l2_bytes' in l:
                    n['s2c_l2_bytes'] = l['l2_bytes']
                if 'l7_bytes' in l:
                    n['s2c_l7_bytes'] = l['l7_bytes']
        r.update(n)

    return result


def get_flow_stats(flowid, token, center_ip, limit=2000):
    route = '/api/1.0/flow/%s/stats' % flowid
    return call_route(route, {'limit': limit}, token, center_ip)


def pd_make_clickable(val):
    # target _blank to open new window
    return '<a target="_blank" href="{}">{}</a>'.format(val, val)


def load_components(filename):
    import pickle
    return pickle.load(open(filename, "rb"))


def _list_props(row):
    return '##'.join(row['properties'].keys())


def _list_tags(row):
    if not 'tags' in row:
        return None
    if not isinstance(row['tags'], dict):
        return None

    return '##'.join(row['tags'].keys())


def extract_prop(row, key1, key2):
    import pandas as pd
    if pd.isnull(row[key1]):
        return None
    if key2 in row[key1]:
        return row[key1][key2]
    return None


def load_components_df(filename, url=None):
    import pandas as pd
    df = pd.DataFrame(load_flows(filename))
    df.index = df['id']
    df['Since'] = pd.to_datetime(df['creation_time'])
    df['Until'] = pd.to_datetime(df['last_active_time'])
    if url:
        df['URL'] = url+"/#/ts/component/"+df['id']

    # Split all properties into columns
    allp = ""
    for c in df.apply(_list_props, axis=1):
        allp = allp + "##" + c
    available_properties = list(set(allp.split('##')))[1:]

    for ap in available_properties:
        df[ap] = df.apply(extract_prop, args=('properties', ap,), axis=1)

    # Split all tags into columns
    allt = ""
    for t in df.apply(_list_tags, axis=1):
        if t:
            allt = allt + "##" + t
    available_tags = list(set(allt.split('##')))[1:]

    for at in available_tags:
        df[at] = df.apply(extract_prop, args=('tags', at,), axis=1)

    return df


def load_flows(filename):
    import pickle
    return pickle.load(open(filename, "rb"))


def load_flows_df(filename, url=None):
    import pandas as pd

    df = pd.DataFrame(load_flows(filename))
    df.index = pd.to_datetime(df['first_seen'])
    df['Since'] = pd.to_datetime(df['first_seen'])
    df['Until'] = pd.to_datetime(df['last_seen'])
    df['Category'] = df['network_category'].astype('category')
    if url:
        df['URL'] = url+"/#/ts/flow/"+df['id']

    try:
        df['Packets'] = df['c2s_packets'] + df['s2c_packets']
        df['Layer 2 Bytes'] = df['c2s_l2_bytes'] + df['s2c_l2_bytes']
        df['Layer 7 Bytes'] = df['c2s_l7_bytes'] + df['s2c_l7_bytes']
    except KeyError:
        print("ERROR: Key Error. Avalaible keys are " + df.keys())
        sys.exit(1)

    return df


def print_flows_stats_df(df):
    print("# Statitics")
    print("- Start:\t%s" % df['Since'].min())
    print("- End:\t\t%s" % df['Until'].max())
    print("- Flows:\t%d" % len(df))
    print("- Total Pkts:\t%d" % df['Packets'].sum())
    print("- Total Bytes:\t%d" % df['Layer 2 Bytes'].sum())


def save_components(filename, components):
    import pickle
    pickle.dump(components, open(filename, "wb"))


def save_flows(flows, filename):
    import pickle
    pickle.dump(flows, open(filename, "wb"))


def save_flow_csv(flows, filename='flows.csv', extra_fields=None, keepid=False):
    import csv
    import copy
    with open(filename, 'w') as csvfile:
        fieldnames = ['src-mac', 'src-ip', 'src-port',
                      'dst-ip', 'dst-mac', 'dst-port',
                      'protocol',
                      'tags', 'network_category',
                      'vlan-id',
                      'properties', 'first_seen', 'last_seen',
                      'c2s_packets', 'c2s_l2_bytes', 'c2s_l7_bytes',
                      's2c_packets', 's2c_l2_bytes', 's2c_l7_bytes',
                      'http-url',
                      'dnstld', 'dnsquestion',
                      'sensor_id', 'ethertype']
        if extra_fields:
            fieldnames = fieldnames + extra_fields
        if keepid:
            fieldnames = fieldnames + ['id', 'src-id', 'dst-id']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        exported = copy.deepcopy(flows)
        for f in exported:
            f.pop('content_id', None)
            if not keepid:
                f.pop('id', None)
                f.pop('src-id', None)
                f.pop('dst-id', None)
            try:
                writer.writerow(f)
            except:
                pass


# Events API


def get_events(token, center_ip, limit=2000):
    route = "/api/1.0/event"
    results = call_route(route, {'limit': limit}, token, center_ip)
    return results

# Severities allowed:
# "0" or "low"
# "1" or "medium"
# "2" or "high"
# "3" or "veryhigh" or "very_high"


def get_last_events(token, center_ip, severity, mins=10):
    route = "/api/1.0/event"
    end = datetime.datetime.now()
    start = end - datetime.timedelta(minutes=int(mins))
    if not isinstance(severity, list):
        severity = [severity]

    parameters = {
        'limit': 1000,
        'start': start.strftime('%Y-%m-%d %H:%M'),
        'end': end.strftime('%Y-%m-%d %H:%M'),
        'severity': severity,
    }
    results = call_route(route, parameters, token, center_ip)
    return results


def get_last_events_seconds(token, center_ip, severity, seconds=2):
    route = "/api/1.0/event"
    end = datetime.datetime.now()
    start = end - datetime.timedelta(seconds=int(seconds))
    if not isinstance(severity, list):
        severity = [severity]

    parameters = {
        'limit': 1000,
        'start': start.strftime('%Y-%m-%d %H:%M:%S'),
        'end': end.strftime('%Y-%m-%d %H:%M:%S'),
        'severity': severity,
    }
    results = call_route(route, parameters, token, center_ip)
    return results

# Tags API


def get_tags(token, center_ip):
    route = '/api/1.0/tags/'
    return call_route(route, {'limit': 2000}, token, center_ip)


def delete_tag(tag_key, token, center_ip):
    route = "/api/1.0/analyzer/tag/%s" % tag_key
    r = delete(route, token, center_ip)
    if (r.status_code != 200):
        print('ERROR: Tag [%s] was not delete, HTTP return '
              'code: %s Text:%s' % (tag_key, str(r.status_code), r.text))
    else:
        print("LOG: %s tag deleted" % tag_key)


def create_tag(tag_key, tag_name, tag_desc, token, center_ip):
    route = "/api/1.0/analyzer/tag"
    tag = {
        "tag": tag_key,
        "label": tag_name,
        "desc": tag_desc
    }
    r = post(route, token, center_ip, json=tag)
    if (r.status_code != 200):
        print('ERROR: Tag [%s] was not added, HTTP return '
              'code: %s Text:%s' % (tag_key, str(r.status_code), r.text))


# Analysers API
def get_analysers_property(token, center_ip):
    route = '/api/1.0/analyzer/property/rule'
    return call_route(route, {'limit': 2000}, token, center_ip)


def get_analysers_port(token, center_ip):
    route = '/api/1.0/analyzer/port/rule'
    return call_route(route, {'limit': 2000}, token, center_ip)


def create_analyser_property(name, json_content, token, center_ip):
    route = "/api/1.0/analyzer/property/rule"
    r = post(route, token, center_ip, data=json_content)
    if (r.status_code != 200):
        print('ERROR: Analyser [%s] was not added, HTTP return '
              'code: %s Text:%s' % (name, str(r.status_code), r.text))


def create_analyser_port(ports, action, tag_key, type_rule, event, token, center_ip):
    route = "/api/1.0/analyzer/port/rule"
    e = False
    if event == 'true':
        e = True
    p = json.loads('{"ports":%s}' % ports)
    rule = {
        "ports": p['ports'],
        "actions": [{
            "name": action,
            "params": {
                "tag": tag_key,
                "type": type_rule,
                "throw_admin_event": e
            }
        }]
    }
    r = post(route, token, center_ip, json=rule)
    if (r.status_code != 200):
        print('ERROR: Analyser [%s -> %s] was not added, HTTP return '
              'code: %s Text:%s' % (ports, tag_key, str(r.status_code), r.text))


def delete_analyser_port(analyser_id, token, center_ip):
    route = "/api/1.0/analyzer/port/rule/%s" % analyser_id
    r = delete(route, token, center_ip)
    if (r.status_code != 200):
        print('ERROR: Analyser [%s] was not delete, HTTP return '
              'code: %s Text:%s' % (analyser_id, str(r.status_code), r.text))


def delete_analyser_property(analyser_id, token, center_ip):
    route = "/api/1.0/analyzer/property/rule/%s" % analyser_id
    r = delete(route, token, center_ip)
    if (r.status_code != 200):
        print('ERROR: Analyser [%s] was not delete, HTTP return '
              'code: %s Text:%s' % (analyser_id, str(r.status_code), r.text))


# Groups API
def get_groups(token, center_ip):
    route = "/api/1.0/group"
    results = call_route(route, {'limit': 1000}, token, center_ip)
    groups = {}
    for r in results:
        groups[r['id']] = r
    return groups

def get_groups_full(token, center_ip):
    route = "/api/1.0/group"
    return call_route(route, {'limit': 1000}, token, center_ip)

def create_group(label, cids, token, center_ip, color='RED', description=''):
    group = {}
    group['label'] = label
    group['description'] = description
    if isinstance(cids, list):
        group['components'] = cids
    else:
        group['components'] = [cids]
    group['color'] = color
    # call the creation group method
    r = post("/api/1.0/group", token, center_ip, json=group)
    if (r.status_code != 200):
        print('ERROR: Group [%s] creation failed, HTTP return code: %s [%s]' % (
            group, str(r.status_code), r.text))


def search_group(groups, label):
    gid = ''
    for i, g in groups.items():
        if g['label'] == label:
            gid = i
    return gid


def add_to_group(label, gid, cid, token, center_ip):
    # Update the group
    r = post("/api/1.0/group/%s/component/%s" % (gid, cid), token, center_ip)
    if (r.status_code != 200):
        print('ERROR: Add to Group - Component [%s] was not added to [%s][%s], HTTP return '
              'code: %s Text:%s' % (cid, label, gid, str(r.status_code), r.text))
    return gid


def delete_all_groups(token, center_ip, quiet=False):
    print("LOG: Deleting all Cyber Vision groups")
    groups = get_groups(token, center_ip)
    if len(groups) == 0:
        print("LOG: No group to delete, exiting...")

    for i, g in groups.items():
        if not quiet:
            print("LOG: Deleting %s" % g['label'])
        delete_group(i, token, center_ip)


def delete_group(gid, token, center_ip):
    # Delete / Explode the group
    r = delete("/api/1.0/group/%s" % gid, token, center_ip)
    if (r.status_code != 200):
        print('ERROR: Group [%s] was not delete, HTTP return '
              'code: %s Text:%s' % (gid, str(r.status_code), r.text))

# Custom Name
# POST a new custom name


def update_custom_name(cid, custom_name, token, center_ip):
    route = '/api/1.0/component/%s/custom-name' % cid
    payload = {'custom_name': custom_name}
    r = put(route, token, center_ip, json=payload)
    if r.status_code != 200:
        print("ERROR: Failed to upsert custom-name "
              "'%s' \nStatus: %s\nText: %s" % (cid, str(r.status_code), r.text))
        return

# Events


def create_event(type_e, severity, family, category, short_message, message, token, center_ip):
    event = {
        "type": type_e,
        "severity": severity,
        "family": family,
        "category": category,
        "shortMessage": short_message,
        "message": message,
    }
    route = '/api/1.0/event/'
    r = put(route, token, center_ip, json=event)
    if r.status_code != 200:
        print("ERROR: Failed to create event "
              "'%s' \nStatus: %s\nText: %s" % (message, str(r.status_code), r.text))
        return

# For simplicity purpose, we create a permissive Context
# which doesn't check the SSL certificates.


def create_unsafe_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

# call_route is an helper to call an API route of the Sentryo CyberVision.
#
# Parameters:
# - route: provide here the route you want to call (e.g. /api/1.0/flow/{id}/content)
# - params: provide a dict which contains all the parameters to provide when calling the route (e.g. { 'id': 'abcd', 'limit': 10, 'offset': 10, })
#
# Returns the content of API response.


def call_route(route, params, token, center_ip):
    # replace the id if any and if provided
    if '{id}' in route:
        if len(params['id']) == 0:
            print(
                'Error: the route contains an ID but you didn\'t provide any to the method `call_route`')
            sys.exit(1)
        route = route.replace('{id}', params['id'])

    route += '?'

    # append parameters
    for key in params.keys():
        if key == 'id':
            continue
        if not isinstance(params[key], list):
            route += '&' + urllib.parse.quote(str(key)) + '=' + \
                    urllib.parse.quote(str(params[key]))
        else:
            for val in params[key]:
                route += '&' + urllib.parse.quote(str(key)) + '=' + \
                    urllib.parse.quote(str(val))
    # finalise the route
    route = url_for(center_ip, route)
    #print("DEBUG: route is %s"%route)

    # launch the request
    try:
        url = urllib.request.Request(route, headers={"X-Token-Id": token})
        r = urllib.request.urlopen(url, context=create_unsafe_ssl_context())
        json_encoding = r.info().get_content_charset('utf-8')
        json_data = json.loads(r.read().decode(json_encoding))
    except:
        print("ERROR: Unable to make a call to %s, exiting..." % route)
        sys.exit(1)

    return json_data


def call_route_recursive(route, token, center_ip, debug=False, max_element=None, params=None):
    results = []
    need_more = True
    offset = 0
    batch_size = 2000

    if max_element and max_element < batch_size:
        batch_size = max_element

    if debug and max_element:
        print("DEBUG: Will call '%s' recursively by batch of %d, stopping if more than %d" % (
            route, batch_size, max_element))
    elif debug:
        print("DEBUG: Will call '%s' recursively by batch of %d, until I'll get everything!" % (
            route, batch_size))

    while need_more:
        if not params:
            params = {}
        params.update({'limit': batch_size, 'offset': offset})
        t = call_route(route, params, token, center_ip)
        print("LOG: Fetched %d elements from %s [offset:%d, batch_size:%d]" %
              (len(t), route, offset, batch_size))
        results = results + t

        # if there is nil answer or we ask for batch_size (ie 2000) and get less, stop
        if len(t) == 0 or batch_size > len(t):
            need_more = False

        # see if we need to request more
        offset = offset + batch_size
        if max_element and (len(t) == 0 or offset >= max_element):
            need_more = False

    return results

# Mac addresses manipulation
def mac_address_addition(src, offset):
    if ':' in src:
        src = src.replace(':','')

    return "{:012x}".format(int(src, 16) + offset)

def post(route, token, center_ip, json=None, data=None):
    route = url_for(center_ip, route)
    headers = {'Content-Type': 'application/json', 'X-Token-Id': token}
    return requests.post(route, json=json, data=data, headers=headers, verify=False)

def put(route, token, center_ip, json=None, data=None):
    route = url_for(center_ip, route)
    headers = {'Content-Type': 'application/json', 'X-Token-Id': token}
    return requests.put(route, json=json, data=data, headers=headers, verify=False)

def delete(route, token, center_ip):
    route = url_for(center_ip, route)
    headers = {'X-Token-Id': token}
    return requests.delete(route, headers=headers, verify=False)

def url_for(center_ip, route):
    return 'https://' + center_ip + route
