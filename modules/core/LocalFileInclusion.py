from multiprocessing import Pool

from util_functions import info
from modules.core.InjectionScannerBase import InjectionScannerBase


class LocalFileInclusion(InjectionScannerBase):
    """ This module is used to scan for local file inclusions, it does this by
        inserting file paths in parameters and checking the resulting page to
        see if the file contents are on the page.
    """

    __wavs_mod__ = True

    info = {
        "name": "Local File Inclusion",
        "desc": "Checks for local file inclusion vulnerability",
        "reportable": True,
        "db_table_name": "lfi_discovered",
        "wordlist_name": "lfi_injection",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main):
        """
            @param main (WebScanner) - a webscanner object to share config
                                       between modules
        """
        self.main = main

        self._create_db_table()

    def _create_db_table(self):
        """ used to create database table needed to store results for this
            module. should be overwritten to meet this modules storage needs

            you should create a SQL statement to create the table, and pass
            the SQL statement to create_table.
        """
        if not self.main.db.table_exists(self.info['db_table_name']):
            sql_create_statement = ('CREATE TABLE IF NOT EXISTS '
                                    f'{self.info["db_table_name"]}('
                                    'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                                    'scan_id INTEGER NOT NULL,'
                                    'page,'
                                    'lfi_param,'
                                    'UNIQUE(page, lfi_param)'
                                    ');')
            self.main.db.create_table(sql_create_statement)

    def _save_scan_results(self, results):
        """ used to save the results of the module to the database

            @param: results -       a list of the results from the module,
                                    should be a list of text
        """
        full_list = []
        for r in results:
            full_list.extend(r)

        # get the successful injections from results
        injections = [(tup[2]) for tup in full_list]

        # remove the injection from results
        full_list = [(tup[0], tup[1]) for tup in full_list]

        self.main.db.save_scan_results(self.main.id,
                                       self.info['db_table_name'],
                                       "page, lfi_param",
                                       full_list)

        self.main.db.update_count(injections, self.info['wordlist_name'])

    def run_module(self):
        info("Searching for local file inclusions...")

        # load in a list of lfi attach strings
        self.attack_strings = self.main.db.get_wordlist(
            self.info['wordlist_name'])

        self.re_search_strings = self.main.db.\
            get_detect_wordlist('lfi')

        # load in params
        injectable_params = self._get_previous_results()

        # create thread pool
        thread_pool = Pool(self.main.options['threads'])

        # map lfi list to threads
        results = thread_pool.map(self._run_thread, injectable_params)

        # join and close the threads
        thread_pool.close()
        thread_pool.join()

        # save the results
        self._save_scan_results(results)

    def get_report_data(self):
        return None
