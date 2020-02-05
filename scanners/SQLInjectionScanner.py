import requests

from datetime import datetime
from multiprocessing import Pool
from functools import partial

from utils import success, warning, info
from utils import db_get_wordlist
from utils import load_scan_results, save_scan_results
from utils import http_get_request

class SQLInjectionScanner:
    __wavs_mod__ = True

    info = {
        "name": "SQL Injection Scanner",
        "desc": "Scan the web application for SQL injections",
        "db_scan_name": "sql_injections",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main, options=None):
        self.main = main

        self.options = {
            # the number of threads the directory scanner should use
            "numberOfThreads": 8
        }

    def _construct_get_url(self, params):
        url = f'http://{self.main.host}:{self.main.port}/{params["action"]}?'

        # http://localhost:80/index.php?username=test&password=test&submit=submit

        for param in params['params']:
            url += f'{param}=test&'

        # remove the last &
        url = url[:-1]

        # urls = []
        # for param in params['params']:
        #     urls.append(url.replace(f'{param}=test', f'{param}=REPLACE'))

        return url


    def _run_thread(self, param):
        method = param['method']
        page = param['action']

        # TODO: get below from database
        sql_injections = ['%27', '%27 OR 1=1', '%27 OR 1=1-- -']
        sql_error_strings = ['unrecognized token', 'syntax error']

        injectable_params = []
        if method == 'GET':
            url = self._construct_get_url(param)

            for p in param['params']:
                for injection in sql_injections:
                    final_url = url.replace(f'{p}=test', f'{p}={injection}')

                    #print(f'Making request: {final_url}')
                    resp = http_get_request(final_url, self.main.cookies)

                    if (any([err_string in resp.text for err_string in sql_error_strings])):
                        if not p in injectable_params:
                            success(f'SQLi vulnerable parameter: {page}/{p}')
                            injectable_params.append(p)

            return injectable_params

        elif method == 'POST':
            # TODO: need to make POST requests
            pass

    def run_module(self):
        info('Searching for SQL injections...')

        # get the injectable params
        #params = self.main.scan_results['params_found']
        params = load_scan_results(self.main.id, 'params_found')

        # pass them off to threads
        thread_pool = Pool(self.options['numberOfThreads'])
        results = thread_pool.map(self._run_thread, params)

        save_scan_results(self.main.id, self.info['db_scan_name'], results)

        thread_pool.close()
        thread_pool.join()
