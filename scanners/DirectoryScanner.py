import requests

from datetime import datetime
from functools import partial
from multiprocessing import Pool

from utils import http_get_request
from utils import success, warning, info
from utils import db_get_wordlist, save_scan_results, db_table_exists, db_create_table

class DirectoryScanner:
    """ This module is used to scan a web application for exposed directories
    """

    __wavs_mod__ = True

    info = {
        "name": "Directory Scanner",
        "db_table_name": "directories_discovered",
        "desc": "Scans a web application for directories",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main):
        self.main = main

        self._create_db_table()

    def _create_db_table(self):
        """ used to create database table needed to store results for this
            module. should be overwritten to meet this modules storage needs
        """
        if not db_table_exists(self.info['db_table_name']):
            sql_create_statement = (f'CREATE TABLE IF NOT EXISTS {self.info["db_table_name"]} ('
                                    f'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                                    f'scan_id INTEGER NOT NULL,'
                                    f'directory TEXT,'
                                    f'UNIQUE(scan_id, directory));')
            db_create_table(sql_create_statement)


    def _load_scan_results(self):
        """ loads in results from previous scans, should be overwritten to load
            in specific results needed for this module
        """

        # dont need to load in anything for this module
        pass

    def _save_scan_results(self, results):
        """ saves the results directories found to the database

            @param results -        a list of directories found
        """
        save_scan_results(self.main.id, self.info['db_table_name'], "directory", results)

    def _run_thread(self, word):
        """ makes a HTTP GET request to check if a directory exists. to be used
            as a thread.

            :param word:        the directory to scan for
            :return (string):   the directory if found
        """
        # check for restricted paths
        if self.main.restrict_paths and word in self.main.restrict_paths:
            return None

        # GET request to the directory
        url = f'http://{self.main.host}:{self.main.port}/{word}/'
        resp = http_get_request(url, self.main.cookies)

        # check if the response code is a success code
        if (resp.status_code in self.main.success_codes):
            if self.main.options['verbose']:
                success(word)
            return word

    def run_module(self):
        start_time = datetime.now()
        # info('Starting directory scan on {}:{} at {}'.format(self.main.host,
        #                                            self.main.port,
        #                                            datetime.strftime(start_time,
        #                                             '%d/%b/%Y %H:%M:%S')))
        info('Searching for directories...')

        # create the threads
        thread_pool = Pool(self.main.options['threads'])

        # load in the wordlist from database
        # word_list = db_get_wordlist('directory', 'general')
        word_list = db_get_wordlist('dir_test', 'general')

        # add an empty string so that the root directory is scanned
        word_list.append('')

        # map the wordlist to threads with _thread_scan method
        directories_found = thread_pool.map(self._run_thread, word_list)

        # remove None results
        directories_found = [directory for directory in directories_found if directory != None]

        # close the threads
        thread_pool.close()
        thread_pool.join()

        # save the directories found to the database
        self._save_scan_results(directories_found)

        end_time = datetime.now()
        #info('Directory search completed. Elapsed: {}'.format(end_time - start_time))
