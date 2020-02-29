from util_functions import info
from multiprocessing import Pool
from modules.core.InjectionScannerBase import InjectionScannerBase


class SQLInjectionScanner(InjectionScannerBase):
    """ This module tests a web application for the SQL injection vulnerability
        it does this by injecting SQL 'attack' strings into parameters and
        checking the resulting webpage for SQL error messages.

        @depends on: HTMLParser
            - this module requires the HTMLParser module to be run before it
              so that it has a list of injectable parameters

        TODO: need to test for blind SQL attacks
    """

    __wavs_mod__ = True

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
        if not self.main.db.db_table_exists(self.info['db_table_name']):
            sql_create_statement = ('CREATE TABLE IF NOT EXISTS '
                                    f'{self.info["db_table_name"]}('
                                    'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                                    'scan_id INTEGER NOT NULL,'
                                    'page TEXT NOT NULL,'
                                    'sql_injection_param TEXT NOT NULL,'
                                    'UNIQUE(scan_id, page, '
                                    'sql_injection_param));')
            self.main.db.db_create_table(sql_create_statement)

    def _save_scan_results(self, results):
        full_list = []
        for r in results:
            full_list.extend(r)

        self.main.db.save_scan_results(self.main.id,
                                       self.info['db_table_name'],
                                       "page, sql_injection_param",
                                       full_list)

    def run_module(self):
        info('Searching for SQL injections...')

        # get the injectable params
        params = self._load_scan_results()
        self.attack_strings = self.main.db.db_get_wordlist('sqli', 'error')
        self.re_search_strings = self.main.db.\
            db_get_wordlist_generic('sql_errors',
                                    'message')
        self.re_search_strings = [s[0] for s in self.re_search_strings]

        # pass them off to threads
        thread_pool = Pool(self.main.options['threads'])
        results = thread_pool.map(self._run_thread, params)

        self._save_scan_results(results)

        thread_pool.close()
        thread_pool.join()
