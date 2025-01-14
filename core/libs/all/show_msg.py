#!/usr/bin/env python3
__author__ = 'Khaled Nassar'
__email__ = 'knassar702@gmail.com'
__version__ = '0.8#Beta'

import random
import logging
import re
from typing import Union
from .colors import Colors
from .requester import Http
from .data import dump_request
from .log import CustomFormatter
from urllib.parse import urlparse
from os import mkdir

# Core Logger
log = logging.getLogger('scant3r')

# Alert Logger
logger = logging.getLogger("alert")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)


# Alert about script results
def alert_script(name: str, command: str, **kwargs) -> dict:
    output = f'\n{Colors.good} {Colors.red}{name}{Colors.rest}: \n -> $ {command}'
    extra_text = ''

    for parameter, value in kwargs.items():
        extra_text += f'\n  {parameter}: {value}'

    output += extra_text + '\n\n----------------------------\n'

    # display the output in console
    logger.info(output)

    try:
        mkdir(f'log/{target}')
        log.debug('Output folder Created')
    except FileExistsError:
        pass
    except Exception as e:
        log.error(e)
        return {}

    # open output file with the name of module and random number from 1 to 100
    output_file = open(f'log/{target}/{name}_{random.randint(1,100)}.txt', 'w')
    output = re.compile(r'''
    \x1B  # ESC
    (?:   # 7-bit C1 Fe (except CSI)
        [@-Z\\-_]
    |     # or [ for CSI, followed by a control sequence
        \[
        [0-?]*  # Parameter bytes
        [ -/]*  # Intermediate bytes
        [@-~]   # Final byte
    )
''', re.VERBOSE).sub('', output)  # remove colors value from text
    output_file.write(output)
    output_file.close()
    return {'Name': name, 'output': kwargs}


# Alert about bugs
def alert_bug(name: str, http: Http, url: Union[str, None] = None, json: bool = False, **kwargs) -> dict:
    output = f'\n{Colors.good} {Colors.red}{name}{Colors.rest}: {http.request.url.split("?")[0]}'
    output += f'\n  Method: {http.request.method}'
    extra_text = ''

    for parameter, value in kwargs.items():
        extra_text += f'\n  {parameter}: {value}'
    output += extra_text
    output += f'''
        ---- Request ----
        {Colors.yellow}
        {dump_request(http)}
        {Colors.rest}
        --------
    '''
    target = urlparse(http.request.url).netloc
    # display the output in console
    if not json:
        logger.info(output)

    try:
        mkdir(f'log/{target}')
        log.debug('Output folder Created')
    except FileExistsError:
        pass
    except Exception as e:
        log.error(e)
        return {}

    # open output file with the name of module and random number from 1 to 100
    output_file = open(f'log/{target}/{name}_{random.randint(1,100)}.txt', 'w')
    output = re.compile(r'''
    \x1B  # ESC
    (?:   # 7-bit C1 Fe (except CSI)
        [@-Z\\-_]
    |     # or [ for CSI, followed by a control sequence
        \[
        [0-?]*  # Parameter bytes
        [ -/]*  # Intermediate bytes
        [@-~]   # Final byte
    )
''', re.VERBOSE).sub('', output)  # remove colors value from text
    output_file.write(output)
    output_file.close()
    if url is None:
        return {'name': name, 'request': dump_request(http), 'output': kwargs}
    else:
        return {'name': name, 'url': url, 'request': dump_request(http), 'output': kwargs}


# Display errors
def show_error(name: str, message: str) -> str:
    output = "\n---- Errors -----"
    output += f"\nModule Name : {name}"
    output += f'\n{message}'
    output += '\n-----------------'
    log.error(output)
    return output
