from modules.core.BaseModule import BaseModule
import concurrent.futures

from util_functions import http_get_request
from util_functions import success, info


class DirectoryScanner(BaseModule):
    """ This module is used to scan a web application for exposed directories


        This module saves its results in the following template:
            {
                 scan_id = # the current scans id,
                 directories = [ # directories found by scan ]
            }
    """

    info = {
        "name": "Directory Scanner",
        "db_table_name": "directories_discovered",
        "wordlist_name": "directory",
        "reportable": False,
        "generate":   True,
        "desc": "Scans a web application for directories",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main):
        BaseModule.__init__(self, main)

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
        url = f'{self.main.get_host_url_base()}/{word}/'
        resp = http_get_request(url, self.main.cookies)

        # check if the response code is a success code
        if (resp.status_code in self.main.success_codes):
            if self.main.options['verbose']:
                success(word, prepend='  ')
            return word

    def run_module(self):
        info('Searching for directories...')

        # load in the wordlist from database
        word_list = self.main.db.get_wordlist(self.info['wordlist_name'])

        # debug word list
        # word_list = ['', 'css', 'data', 'images', 'js']

        # add an empty string so that the root directory is scanned
        # word_list.append('')

        # map the wordlist to threads with _thread_scan method
        with concurrent.futures.ProcessPoolExecutor() as executor:
            directories_found = list(executor.map(self._run_thread, word_list))

        # remove None results
        directories_found = [directory
                             for directory
                             in directories_found
                             if directory is not None]

        # save the directories found to the database
        self._save_scan_results(directories_found)
