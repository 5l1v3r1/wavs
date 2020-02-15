import requests

from datetime import datetime
from functools import partial
from multiprocessing import Pool

from utils import db_get_wordlist, db_table_exists, db_create_table, load_scan_results, db_get_wordlist_generic, save_scan_results
from utils import http_get_request
from utils import success, warning, info
from scanners.InjectionScannerBase import InjectionScannerBase

class CrossSiteScripting(InjectionScannerBase):
    """ This module is used to scan for local file inclusions, it does this by
        inserting file paths in parameters and checking the resulting page to
        see if the file contents are on the page.
    """

    __wavs_mod__ = True

    info = {
        "name": "Cross Site Scripting",
        "desc": "Checks for cross site scripting vulnerabilities",
        "db_table_name": "xss_discovered",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main):
        """
            @param main (WebScanner) - a webscanner object to share configuration
                                       between modules
        """
        self.main = main

        self._create_db_table()

    def _create_db_table(self):
        """ used to create database table needed to store results for this
            module. should be overwritten to meet this modules storage needs

            you should create a SQL statement to create the table, and pass
            the SQL statement to db_create_table.
        """
        if not db_table_exists(self.info['db_table_name']):
            sql_create_statement = (f'CREATE TABLE IF NOT EXISTS {self.info["db_table_name"]}('
                                    f'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                                    f'scan_id INTEGER NOT NULL,'
                                    f'page,'
                                    f'xss_param,'
                                    f'UNIQUE(page, xss_param)'
                                    f');')
            db_create_table(sql_create_statement)

    def _save_scan_results(self, results):
        """ used to save the results of the module to the database

            @param: results -       a list of the results from the module, should
                                    be a list of text
        """
        full_list = []
        for r in results:
            full_list.extend(r)

        save_scan_results(self.main.id, self.info['db_table_name'], "page, xss_param", full_list)


    def run_module(self):
        info("Searching for cross site scripting...")

        # load in a list of lfi attach strings
        self.attack_strings = db_get_wordlist_generic('xss', 'word')
        self.attack_strings = [s[0] for s in self.attack_strings]

        # the search strings will be the attack strings themselves
        # because python will not interpret any javascript
        self.re_search_strings = self.attack_strings

        # load in params
        injectable_params = self._load_scan_results()

        # create thread pool
        thread_pool = Pool(self.main.options['threads'])

        # map lfi list to threads
        results = thread_pool.map(self._run_thread, injectable_params)

        # join and close the threads
        thread_pool.close()
        thread_pool.join()

        # save the results
        self._save_scan_results(results)
