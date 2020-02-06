import requests

from datetime import datetime
from functools import partial
from multiprocessing import Pool

from utils import db_get_wordlist
from utils import success, warning, info
from utils import http_get_request, http_post_request
from utils import load_scan_results, save_scan_results, db_table_exists, db_create_table

class SQLInjectionScanner:
    """ This module tests a web application for the SQL injection vulnerability,
        it does this by injecting SQL 'attack' strings into parameters and checking
        the resulting webpage for SQL error messages.

        @depends on: HTMLParser
            - this module requires the HTMLParser module to be run before it
              so that it has a list of injectable parameters

        TODO: need to test for blind SQL attacks
    """
    info = {
        "name": "SQL Injection Scanner",
        "desc": "Scan the web application for SQL injections",
        "db_table_name": "sql_injections",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main, options=None):
        self.main = main

        self._create_db_table()

    def _create_db_table(self):
        """ used to create database table needed to store results for this
            module. should be overwritten to meet this modules storage needs
        """
        if not db_table_exists(self.info['db_table_name']):
            sql_create_statement = (f'CREATE TABLE IF NOT EXISTS {self.info["db_table_name"]}('
                                    f'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                                    f'scan_id INTEGER NOT NULL,'
                                    f'page TEXT NOT NULL,'
                                    f'sql_injection_param TEXT NOT NULL,'
                                    f'UNIQUE(scan_id, page, sql_injection_param));')
            db_create_table(sql_create_statement)


    def _load_scan_results(self):
        """ loads in results from previous scans, should be overwritten to load
            in specific results needed for this module
        """
        # load directories from database, results are a list of tuples
        inject_params = load_scan_results(self.main.id, 'method, action, parameter', 'parameters_discovered')
        return inject_params

    def _save_scan_results(self, results):
        full_list = []
        for r in results:
            full_list.extend(r)

        save_scan_results(self.main.id, self.info['db_table_name'], "page, sql_injection_param", full_list)

    def _construct_get_url(self, page, params):
        url = f'http://{self.main.host}:{self.main.port}/{page}?'

        # http://localhost:80/index.php?username=test&password=test&submit=submit

        for param in params:
            url += f'{param}=test&'

        # remove the last &
        url = url[:-1]

        return url

    def _construct_post_params(self, params):
        param_dict = {}
        for p in params:
            param_dict['p'] = 'test'


    def _run_thread(self, param):
        method = param[0]
        page = param[1]

        # TODO: get below from database
        sql_injections = ['%27', '%27 OR 1=1', '%27 OR 1=1-- -']
        sql_error_strings = ['unrecognized token', 'syntax error']

        injectable_params = []
        inject_params = param[2].split(', ')

        if method == 'GET':
            url = self._construct_get_url(page, inject_params)

            for p in inject_params:
                for injection in sql_injections:
                    final_url = url.replace(f'{p}=test', f'{p}={injection}')

                    resp = http_get_request(final_url, self.main.cookies)

                    if (any([err_string in resp.text for err_string in sql_error_strings])):
                        if not p in injectable_params:
                            if self.main.options['verbose']:
                                success(f'SQLi vulnerable parameter: {page}/{p}')
                            injectable_params.append((page, p))

            return injectable_params

        elif method == 'POST':
            # construct the url to make the request to
            url = f'http://{self.main.host}:{self.main.host}/{page}'
            params =

    def run_module(self):
        info('Searching for SQL injections...')

        # get the injectable params
        #params = self.main.scan_results['params_found']
        params = self._load_scan_results()

        # pass them off to threads
        thread_pool = Pool(self.main.options['threads'])
        results = thread_pool.map(self._run_thread, params)

        self._save_scan_results(results)

        thread_pool.close()
        thread_pool.join()
