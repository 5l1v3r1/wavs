import requests

from datetime import datetime
from functools import partial
from multiprocessing import Pool

from utils import db_get_wordlist
from utils import http_get_request
from utils import success, warning, info

class ScannerTemplate:
    """ This is a template used to create custom modules that run scans on the
        web application. The module can optionally load in the results of
        previous scans, and save results to the database.

        The module should be saved in the scanners/ directory, and the filename
        should be the same as the class name, e.g. The ScannerTemplate class
        would be saved in scanners/ScannerTemplate.py.

        Module loading:
            To load the module into the application an entry needs to be made in
            the conf/config.json file under 'modules' with the name and the path
            to the file. e.g.
            { "name" : "Scanner Template", "path" : "scanners/ScannerTemplate" }

            Then add the module name in 'scan types', either in an existing scan
            category, or a new one.

        @required properties:
            __wavs_mod__ - module must contain this propery and it must be true
            info['name'] - the name of the module, needs to match name in the
                           conf/config.json file to correctly load the module

        @optional properties:
            info['db_table_name'] - the name of the table created in _create_db_table()

        @required methods:
            run_module - the entry point of the module, should start the scan

        @optional methods:
            _create_db_table - use to create a table in the database to store results
                               should be called from __init__()
            _save_scan_results - use to save results to database
            _load_scan_results - use to load other module results
            _run_thread - use to implement threading, use with multiprocessing.Pool
    """

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
