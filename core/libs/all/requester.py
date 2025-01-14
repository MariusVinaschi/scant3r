#!/usr/bin/env python3
__author__ = 'Khaled Nassar'
__email__ = 'knassar702@gmail.com'
__version__ = '0.8#Beta'

import time
import random
import logging
import json
from typing import Union
from requests import Request, Session, request, packages
from requests.models import Response
from .data import post_data, dump_request, dump_response

# ignore ssl warning messages
packages.urllib3.disable_warnings()

# scant3r logger
log = logging.getLogger('scant3r')

# Create an User Agent
# Choice one user agent from  the text file agents.txt
# Another Solution : https://github.com/hellysmile/fake-useragent


class Agent:
    def __init__(self):
        self.all = ['Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:86.0) Gecko/20100101 Firefox/86.0']
        self.random = random.choice(self.all)

    def load(self):
        try:
            with open('wordlists/txt/agents.txt', 'r') as aw:
                for i in aw:
                    if len(i.rstrip()) > 1:
                        self.all.append(i.rstrip())
            self.random = random.choice(self.all)
        except Exception as e:
            log.error(e)
            return


class Http:
    def __init__(self, opts: dict):
        self.timeout = opts['timeout']
        self.headers = opts['headers']
        self.cookies = opts['cookies']
        self.random_agents = opts['random_agents']
        self.debug = opts['debug']
        self.proxy: dict = opts['proxy']
        self.allow_redirects: bool = opts['allow_redirects']
        self.delay = opts['delay']
        self.count: int = 0
        self.content_types: list = opts['content_types']

    # Send a request
    def send(self,
             method: str = 'GET',
             url: Union[str, None] = None,
             body: dict = {},
             headers: dict = {},
             allow_redirects: bool = False,
             org: bool = True,
             files: Union[dict, None] = None,
             timeout: int = 10,
             ignore_errors: bool = False,
             remove_content_type: bool = False,
             convert_content_type: str = 'plane') -> Response:
        try:
            # Generate user agent
            user_agents = Agent()
            if self.random_agents:
                user_agents.load()

            # Add user agent to headers
            if 'User-agent' not in headers.keys():
                headers['User-agent'] = user_agents.random

            # set headers
            if self.headers:
                for header, value in self.headers.items():
                    if not self.cookies and 'Cookie' in header:
                        headers[header] = value

            # Specify cookie
            cookies = {}
            if self.cookies:
                cookies = self.cookies

            # follow 302 redirects
            allow_redirects = False
            if self.allow_redirects:
                allow_redirects = True

            # Set timeout
            if timeout == 10 and self.timeout:
                timeout = self.timeout

            # set proxy
            proxy = {}
            if type(self.proxy) is dict:
                proxy = self.proxy

            # convert body to parameters
            if org:
                if type(body) is str:
                    log.debug('convert body to dict')
                    if body.startswith('?'):
                        pass
                    else:
                        body = '?' + body
                    body = post_data(body)

                if method != 'GET' and not body:
                    log.debug('convert body to dict')
                    body = post_data(url)
                    url = url.split('?')[0]

            if self.content_types:
                for content_type in self.content_types:
                    if content_type.split('/')[1] == 'json' and method != 'GET':
                        log.debug('convert body to json query')
                        # convert query parameters to json
                        body = json.dumps(body)
                    headers['Content-Type'] = content_type

            if convert_content_type == 'json' and method != 'GET':
                body = json.dumps(body)
                headers['Content-Type'] = 'application/json'

            if remove_content_type:
                del headers['Content-Type']

            req = request(
                method,
                url,
                data=body,
                headers=headers,
                cookies=cookies,
                files=files,
                allow_redirects=allow_redirects,
                verify=False,
                timeout=timeout,
                proxies=proxy
            )

            if self.delay > 0:
                log.debug(f'sleep {self.delay}')
                time.sleep(self.delay)

            # number of request
            self.count += 1
            req.encoding = req.apparent_encoding

            # show request and response (-d option)
            if self.debug:
                print(f'--- [#{self.count}] Request ---')
                print(dump_request(req))
                print('\n---- RESPONSE ----')
                print(dump_response(req))
                print('--------------------\n\n')

            return req
        except Exception as e:
            if ignore_errors is False:
                log.error(e)
            return [0, e]

    # send a request with custom options (without user options)
    def custom(self,
               method='GET',
               url=None,
               body={},
               headers={},
               timeout=10,
               allow_redirects=False,
               proxy={}):
        try:
            time.sleep(self.delay)
            req = Request(method, url, data=body, headers=headers)
            s = Session()
            res = s.send(
                req.prepare(),
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=False,
                proxies=proxy
            )
            return res
        except Exception as e:
            log.error(e)
            return [0, e]
