# -*- coding: utf-8 -*-
"""
Cyber Vision Client API to communicate with all APIs 

Public API (Using a token, see Cyber Vision web application > Administration > API)

Public API:
    APISession class creates a session context where all further
    requests will contains the provided token header.
    Just use .get(), .post(), .put(), .delete() methods.
    APISession is wrapping Python famous requests lib within a requests session
    and each requests returns a requests.Response instance.

    Example:
        Using a context manager

            with APISession('10.7.0.20', 443, 'ics-my-token') as s:
                resp = s.get('/api/3.0/components')
                components = resp.json()

        Or without context manager:

            s = APISession('10.7.0.20', 443, 'ics-my-token')
            resp = s.get('/api/3.0/components')
            components = resp.json()

"""
import requests
import urllib3
import sys
from urllib.parse import urljoin


def pp_request(req: requests.Request):
    """
    Pretty print requests.Request HTTP request
    """
    print(
        "{}\r\n{}\r\n".format(
            req.method + " " + req.url,
            "\r\n".join("{}: {}".format(k, v) for k, v in req.headers.items()),
        )
    )
    if hasattr(req, "body"):
        print(req.body)


def pp_response(resp: requests.Response):
    """
    Pretty print request.Response HTTP response
    """
    print(
        "{}\r\n{}\r\n\r\n{}".format(
            "HTTP1/1" + " " + str(resp.status_code) + " " + resp.reason,
            "\r\n".join("{}: {}".format(k, v) for k, v in resp.headers.items()),
            resp.content,
        )
    )

def get_route(session, route, params=None, headers=None):
    ret = session.get(route,headers=headers, params=params)
    if ret.status_code != 200:
        print(f"Unable to fetch '{route}' return code {ret.status_code}")
        sys.exit(1)
    return ret.json()

def get_route_recursive(session, route,max_element=None, params=None, headers=None):
    results = []
    need_more = True
    offset = 0
    batch_size = 2000

    if max_element and max_element < batch_size:
        batch_size = max_element

    #if max_element:
    #    print("DEBUG: Will call '%s' recursively by batch of %d, stopping if more than %d"%(route, batch_size,max_element))
    #else:
    #    print("DEBUG: Will call '%s' recursively by batch of %d, until I'll get everything!"%(route, batch_size))

    if not params:
        params = {}

    while need_more:    
        params.update({'limit':str(batch_size), 'offset':str(offset)})
        t = get_route(session, route,headers=headers,params=params)
        print("LOG: Fetched %d elements from %s [offset:%d, batch_size:%d]"%
              (len(t),route,offset,batch_size))
        results = results + t

        # if there is nil answer or we ask for batch_size (ie 2000) and get less, stop
        if len(t)== 0 or batch_size > len(t):
            need_more = False

        # see if we need to request more
        offset = offset + batch_size
        if max_element and (len(t)== 0 or offset >= max_element):
            need_more = False

    print("LOG: Total fetched %d"%len(results))    

    return results


def post_route(session, route, json):
    #print(f"DEBUG: [POST] Calling {route}")
    #print(f"DEBUG: [POST] Payload: {json}")
    return session.post(route,json=json)

def delete_route(session, route, json):
    #print(f"DEBUG: [POST] Calling {route}")
    #print(f"DEBUG: [POST] Payload: {json}")
    return session.delete(route,json=json)

def patch_route(session, route, json):
    #print(f"DEBUG: [PATCH] Calling {route}")
    #print(f"DEBUG: [PATCH] Payload: {json}")
    return session.patch(route,json=json)


def put_route(session, route, json):
    return session.put(route, json=json)


class APISession:
    """
    Gives a Cyber Vision session to call the public API endpoints
    Don't make call to private SCV api endpoints,
    it will fail, use SCVSession instead
    """

    def __init__(self, host: str, port: int, token: str, proxy: str):
        urllib3.disable_warnings()
        self.host = host
        self.port = port
        self.token = token
        self.proxy = proxy

    def _get_url(self, endpoint):
        return urljoin(f"https://{self.host}:{self.port}", endpoint)

    def get(self, endpoint, *args, **kwargs):
        return self.session.get(self._get_url(endpoint), *args, **kwargs)

    def post(self, endpoint, *args, **kwargs):
        return self.session.post(self._get_url(endpoint), *args, **kwargs)

    def put(self, endpoint, *args, **kwargs):
        return self.session.put(self._get_url(endpoint), *args, **kwargs)

    def delete(self, endpoint, *args, **kwargs):
        return self.session.delete(self._get_url(endpoint), *args, **kwargs)

    def patch(self, endpoint, *args, **kwargs):
        return self.session.patch(self._get_url(endpoint), *args, **kwargs)

    def head(self, endpoint, *args, **kwargs):
        return self.session.head(self._get_url(endpoint), *args, **kwargs)

    def options(self, endpoint, *args, **kwargs):
        return self.session.options(self._get_url(endpoint), *args, **kwargs)

    def __enter__(self):
        self.session = requests.Session()
        self.session.verify = False
        if self.proxy != '':
            self.session.proxies = {'http': self.proxy, 'https': self.proxy}

        # Add token to every requests
        self.session.headers.update({"x-token-id": self.token})

        return self

    def __exit__(self, exc_type, exc, exc_tb):
        self.close()

    def close(self):
        self.session.close()


