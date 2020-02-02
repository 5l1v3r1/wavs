import requests

from datetime import datetime
from multiprocessing import Pool
from functools import partial

from utils import success, warning, info
from utils import db_get_wordlist, save_scan_results
from utils import http_get_request

class DirectoryScanner:
    __wavs_mod__ = True

    info = {
        "name": "Directory Scanner",
        "desc": "Scans a web application for directories",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main, options=None):
        self.main = main

        self.options = {
            # the number of threads the directory scanner should use
            "numberOfThreads": 8,
            "verbose": 1
        }

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
        thread_pool = Pool(self.options['numberOfThreads'])

        # load in the wordlist from database
        word_list = db_get_wordlist('directory', 'general')

        # add an empty string so that the root directory is scanned
        word_list.append('')

        # map the wordlist to threads with _thread_scan method
        directories_found = thread_pool.map(self._run_thread, word_list)

        # remove None results
        directories_found = [directory for directory in directories_found if directory != None]

        # close the threads
        thread_pool.close()
        thread_pool.join()

        self.main.scan_results['directories_found'].extend(directories_found)

        end_time = datetime.now()
        #info('Directory search completed. Elapsed: {}'.format(end_time - start_time))
