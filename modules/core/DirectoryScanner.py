from BaseModule import BaseModule
from multiprocessing import Pool

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
        "desc": "Scans a web application for directories",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main):
        BaseModule.__init__(self, main)

    def _save_scan_results(self, results):
        """ saves the results directories found to the database

            @param results -        a list of directories found
        """
        table = self.main.db.table(self.info['db_table_name'])

        table.insert({
            "scan_id": self.main.id,
            "directories": results
        })

        # update wordlist count for successful words
        self.main.db.update_count(results, self.info['wordlist_name'])

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

        # create the threads
        thread_pool = Pool(self.main.options['threads'])

        # load in the wordlist from database
        # word_list = get_wordlist('directory', 'general')
        word_list = self.main.db.get_wordlist(self.info['wordlist_name'])

        # add an empty string so that the root directory is scanned
        word_list.append('')

        # map the wordlist to threads with _thread_scan method
        directories_found = thread_pool.map(self._run_thread, word_list)

        # remove None results
        directories_found = [directory
                             for directory
                             in directories_found
                             if directory is not None]

        # close the threads
        thread_pool.close()
        thread_pool.join()

        # save the directories found to the database
        self._save_scan_results(directories_found)
