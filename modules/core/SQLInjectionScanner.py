import concurrent.futures
from util_functions import info, warning
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

    info = {
        "name":             "SQL Injection Scanner",
        "desc":             "Scan the web application for SQL injections",
        "reportable":       True,
        "db_table_name":    "sql_injections",
        "wordlist_name":    "sql_injection",
        "author":           "@ryan_ritchie"
    }

    def __init__(self, main):
        InjectionScannerBase.__init__(self, main)

    def run_module(self):
        info('Searching for SQL injections...')

        # get the injectable params
        params = self._get_previous_results('HTMLParser')
        self.attack_strings = self.main.db.get_wordlist(
            self.info['wordlist_name'])
        self.re_search_strings = self.main.db.\
            get_detect_wordlist('sql')

        # pass them off to threads
        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = list(executor.map(self._run_thread, params))

        final = []
        for r in results:
            final.extend(r)
        self._save_scan_results(final)
