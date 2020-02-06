import requests

from datetime import datetime
from functools import partial
from multiprocessing import Pool

from utils import db_get_wordlist
from utils import http_get_request
from utils import success, warning, info

class CrossSiteScripting:
    """ This module is used to scan for cross site scripting (XSS) vulnerabilities
        in a web application. It does this
    """

    __wavs_mod__ = True

    info = {
        "name": "",
        "desc": "",
        "db_table_name": "",
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
                                    f'<add columns here>,'
                                    f');')
            db_create_table(sql_create_statement)

    def _save_scan_results(self, results):
        """ used to save the results of the module to the database

            @param: results -       a list of the results from the module, should
                                    be a list of text
        """
        pass

    def _load_scan_results(self):
        """ loads in results from previous scans, should be overwritten to load
            in specific results needed for this module
        """
        pass

    def _run_thread(self):
        pass

    def run_module(self):
        pass
