import requests

from datetime import datetime
from multiprocessing import Pool
from functools import partial

from utils import success, warning, info
from utils import db_get_wordlist
from utils import http_get_request

class FileScanner:
    __wavs_mod__ = True

    info = {
        "name": "File Scanner",
        "desc": "Scans for files once ",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main, options=None):
        self.main = main

        self.options = {
            # the number of threads the directory scanner should use
            "numberOfThreads": 8,

            # how much information should it output
            "verbose": 1,

            # what directories should it scan for files in
            "directories": self.main.scan_results['directories_found']
        }

    def _parse_options(self, options):
        # parse the options
        for opt in options:
            if opt in self.options.keys():
                self.options[opt] = options[opt]

    def _run_thread(self, directory, word):
        """ makes a HTTP GET request to check if a file exists. to be used as
            a thread.

            :param directory:       the directory to search for files in
            :param word:            the file name to search for
            :return (list):         a list of found files
        """
        found_files = []

        # construct the url to be used in the GET request
        url = 'http://{}:{}/'.format(self.main.host, self.main.port)
        if directory:
            url += (directory + '/')

        # loop through file extensions to be searched for
        for ext in self.main.file_extensions:
            # make the GET request for the file
            resp = http_get_request(url + f'{word}{ext}')

            # check if the response code is a success code
            if (resp.status_code in self.main.success_codes):
                # if the directory is not an empty string i.e. if it is not
                # searching the root directory
                found_path = ''
                if directory:
                    found_path = f'{directory}/{word}{ext}'
                else:
                    found_path = f'{word}{ext}'

                if self.options['verbose']:
                    success(found_path)

                found_files.append(found_path)

        # only return a list if files were actually found
        if found_files:
            return found_files

    def _run_module(self):
        """ method that loads in a file wordlist and uses thread to search for
            the files

            :return:
        """
        start_time = datetime.now()
        info('Starting file scan on {}:{} at {}'.format(self.main.host,
                                                   self.main.port,
                                                   datetime.strftime(start_time,
                                                    '%d/%b/%Y %H:%M:%S')))

        # TODO: create a file wordlist
        word_list = db_get_wordlist('directory', 'general')

        # create the threads
        # need to let user change the number of threads used
        thread_pool = Pool(self.options['numberOfThreads'])

        files_found = []

        # loop through the list of directories found by _dir_scanner
        for directory in self.options['directories']:
            # use partial to allow more parameters passed to map
            func = partial(self._run_thread, directory)

            # use threads to scan for files
            files_found += thread_pool.map(func, word_list)

        # remove None results
        files_found = [file for file in files_found if file != None]
        files_found = [file for sublist in files_found for file in sublist]

        thread_pool.close()
        thread_pool.join()

        self.main.scan_results['files_found'].extend(files_found)

        end_time = datetime.now()
        info('File search completed. Elapsed: {}'.format(end_time - start_time))
