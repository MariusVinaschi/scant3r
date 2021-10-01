from .sqli import Sqli
from core.libs import Http, alert_bug
from logging import getLogger

log = getLogger('scant3r')


def main(opts: dict, http: Http):
    result = Sqli(opts, http).start()

    if ("message" in result.keys() and
            result["message"] == "vulnerabilities" and
            "vulns" in result.keys() and
            type(result['vulns']) is list):

        list_sqli = []
        for vuln in result['vulns']:
            sqli = alert_bug(
                vuln['vuln'],
                vuln['response'],
                json=opts['json'],
                **{
                    'payload': vuln['payload'],
                    'match': vuln['match'],
                }
            )
            list_sqli.append(sqli)

        if opts['json']:
            print(list_sqli)

    else:
        log.debug('SQLI: No vuln find')
