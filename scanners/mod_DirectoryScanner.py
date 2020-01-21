import requests

from utils import success, warning, info
from utils import db_get_wordlist
from datetime import datetime
from multiprocessing import Pool
from functools import partial

class DirectoryScanner:
    __wavs_mod__ = True

    self.info = {
        "name": "Directory Scanner",
        "desc": "Scans a web application for directories",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main, options=None):
        self.main = main

        self.options = {
            # the number of threads the directory scanner should use
            "numberOfThreads": 8
        }

    def _run_thread(self, word):
        """ makes a HTTP GET request to check if a directory exists. to be used
            as a thread.

            :param word:        the directory to scan for
            :return (string):   the directory if found
        """
        # GET request to the directory
        resp = requests.get('http://{}:{}/{}/'.format(self.main.host,
                                                      self.main.port,
                                                      word))

        # check if the response code is a success code
        if (resp.status_code in self.main.success_codes):
            return word

    def _run_module(self):
        start_time = datetime.now()
        info('Starting scan on {}:{} at {}'.format(self.main.host,
                                                   self.main.port,
                                                   datetime.strftime(start_time,
                                                    '%d/%b/%Y %H:%M:%S')))

        # create the threads
        # TODO: allow the user to change number of threads
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

        self.main.directories_found = directories_found

        end_time = datetime.now()
        info('Directory search completed. Elapsed: {}'.format(end_time - start_time))
