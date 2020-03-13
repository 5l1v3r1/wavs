from BaseModule import BaseModule
from functools import partial
from multiprocessing import Pool
from tinydb import where

from util_functions import http_get_request
from util_functions import success, info


class FileScanner(BaseModule):
    """
        This module saves its results in the following template:
            {
                 scan_id = # the current scans id,
                 files = [ # files found by scan ]
            }
    """
    info = {
        "name": "File Scanner",
        "db_table_name": "files_discovered",
        "wordlist_name": "file",
        "reportable": False,
        "desc": "Scans for files once ",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main):
        BaseModule.__init__(self, main)

    def _get_previous_results(self):
        """ this module uses results from DirectoryScanner module, it uses
            the directories found by that module, and searches for files
            within those directories. If no directories were found, or
            DirectoryScanner was not run, this module will search the base
            directory '/'.
        """
        # import DirectoryScanner so we can get the table name
        try:
            from DirectoryScanner import DirectoryScanner
        except ImportError:
            return []

        # get the table name DirectoryScanner uses to save data
        table_name = DirectoryScanner.info['db_table_name']

        # get the instance of the table DirectoryScanner uses
        table = self.main.db.table(table_name)

        # load in the data directories found in this scan
        return table.get(where('scan_id') == self.main.id)['directories']

    def _save_scan_results(self, results):
        """ saves the files found during the scan to the database
        """
        table = self.main.db.table(self.info['db_table_name'])

        table.insert({
            "scan_id": self.main.id,
            "files": results
        })

        # update wordlist count for successful words
        self.main.db.update_count(results, self.info['wordlist_name'])

    def _run_thread(self, directory, word):
        """ makes a HTTP GET request to check if a file exists. to be used as
            a thread.

            :param directory:       the directory to search for files in
            :param word:            the file name to search for
            :return (list):         a list of found files
        """
        found_files = []

        # construct the url to be used in the GET request
        url = f'{self.main.get_host_url_base()}/'
        if directory:
            url += (directory + '/')

        # loop through file extensions to be searched for
        for ext in self.main.file_extensions:
            # check we dont go to restricted path
            if self.main.restrict_paths:
                if f'{word}{ext}' in self.main.restrict_paths:
                    continue

            # make the GET request for the file
            resp = http_get_request(url + f'{word}{ext}', self.main.cookies)

            # check if the response code is a success code
            if (resp.status_code in self.main.success_codes):
                # if the directory is not an empty string i.e. if it is not
                # searching the root directory
                found_path = ''
                if directory:
                    found_path = f'{directory}/{word}{ext}'
                else:
                    found_path = f'{word}{ext}'

                if self.main.options['verbose']:
                    success(found_path, prepend='  ')

                found_files.append(found_path)

        # only return a list if files were actually found
        if found_files:
            return found_files

    def run_module(self):
        """ method that loads in a file wordlist and uses thread to search for
            the files

            :return:
        """
        info('Searching for files...')

        # TODO: create a file wordlist
        # word_list = get_wordlist('directory', 'general')
        word_list = self.main.db.get_wordlist(self.info['wordlist_name'])

        # create the threads
        # need to let user change the number of threads used
        thread_pool = Pool(self.main.options['threads'])

        files_found = []

        # loop through the list of directories found by _dir_scanner
        dirs_discovered = self._get_previous_results()

        # if there are no dirs found
        if not dirs_discovered:
            dirs_discovered.append('')

        for directory in dirs_discovered:
            # use partial to allow more parameters passed to map
            func = partial(self._run_thread, directory)

            # use threads to scan for files
            files_found += thread_pool.map(func, word_list)

        # remove None results
        files_found = [file for file in files_found if file is not None]
        files_found = [file for sublist in files_found for file in sublist]

        thread_pool.close()
        thread_pool.join()

        self._save_scan_results(files_found)

    def get_report_data(self):
        return None
