#!/usr/bin/env python3
__author__ = 'Khaled Nassar'
__email__ = 'knassar702@gmail.com'
__version__ = '0.8#Beta'

from .colors import Colors as c
from .data import dump_request
from urllib.parse import urlparse 
from logging import getLogger
from os import mkdir
import random, re

log = getLogger('scant3r')

# Alert about bugs
def alert_bug(name,http,**kwargs) -> dict:
    output = f'\n{c.good} {c.red}{name}{c.rest}: {http.request.url.split("?")[0]}'
    output += f'\n  Method: {http.request.method}'
    extra_text = ''
    for parameter,value in kwargs.items():
        extra_text += f'\n  {parameter}: {value}'
    output += extra_text
    output += f'''
        ---- Request ----
        {c.yellow}
{dump_request(http)}
        {c.rest}
        --------
    '''
    target = urlparse(http.request.url).netloc
    # display the output in console
    log.info(output)
    try:
        mkdir(f'log/{target}')
    except:
        pass
    # open output fule with the name of module and random number from 1 to 100
    output_file = open(f'log/{target}/{name}_{random.randint(1,100)}.txt','w')
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
''', re.VERBOSE).sub('',output) # remove colors value from text
    output_file.write(output)
    output_file.close()
    return {'Name':name,
            'request':dump_request(http),
            'output':kwargs
            }


# Display errors
def show_error(name : str, message : str):
    f = "\n---- Errors -----"
    f += f"\nModule Name : {name}"
    f += f'\n{message}'   
    f += '\n-----------------'
    log.error(f)
