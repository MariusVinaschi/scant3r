from .xss import Xss
from urllib.parse import urlparse as ur
from core.libs import alert_bug
from core.libs import Http
from logging import getLogger

log = getLogger('scant3r')


def main(opts: dict, http: Http):
    # If Query in the URL
    if ur(opts['url']).query:
        result = Xss(opts, http).start()
        if ("message" in result.keys() and
                result["message"] == "vulnerabilities" and
                "vulns" in result.keys() and
                type(result['vulns']) is list):

            list_xss = []
            for vuln in result['vulns']:
                xss = alert_bug(
                    vuln['vuln'],
                    vuln['response'],
                    json=opts['json'],
                    **{
                        'params': vuln['params'],
                        'payload': vuln['payload'],
                    }
                )    
                list_xss.append(xss)

            if opts['json']:
                print(list_xss)
        else:
            log.debug('XSS: No Vuln find')
    else:
        log.debug('XSS: NO URL QUERY')
