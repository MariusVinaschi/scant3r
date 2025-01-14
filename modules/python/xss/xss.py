#!/usr/bin/env python3
from core.libs import random_str, insert_to_params_urls, Http
from urllib.parse import urlparse
from wordlists import XSS
from modules import Scan


class Xss(Scan):
    def __init__(self, opts: dict, http: Http):
        super().__init__(opts, http)
        self.payloads = XSS(opts['blindxss']).payloads

    def check_method(self, methods: list, url: str) -> dict:
        method_allowed = dict()
        for method in methods:
            method_allowed[method] = {}
            response = self.http.send(method, url)

            if response != 0 and response.status_code != 405:
                method_allowed[method] = {url: response.status_code}

        return method_allowed

    def start(self) -> dict:
        list_xss = []
        for method in self.opts['methods']:
            list_potential_vulnerable_url: list = []
            txt = f'scan{random_str(3)}tr'

            # Create a list of url with value for each parameter
            # if text is display append it in ref list

            target_url = self.transform_url(self.opts['url'])
            new_url = insert_to_params_urls(target_url, txt)
            response = self.send_request(method, new_url)

            if type(response) is not list:
                if txt in response.text:
                    list_potential_vulnerable_url.append(new_url)

                for potential_vulnerable_url in list_potential_vulnerable_url:
                    for payload in self.payloads:
                        # remove new lines from payloads
                        payload = payload.rstrip()
                        # replace the text by the payload
                        payload_url = potential_vulnerable_url.replace(txt, payload)
                        response = self.send_request(method, payload_url)
                        if response != 0 and payload in response.text:
                            list_xss.append({
                                'vuln': 'XSS',
                                "response": response,
                                'params': urlparse(payload_url).query,
                                "payload": payload
                            })

        if len(list_xss) > 0:
            return {
                "message": "vulnerabilities",
                "vulns": list_xss
            }

        return {
            "message": "No xss find in this url",
            "url": self.opts['url']
        }
