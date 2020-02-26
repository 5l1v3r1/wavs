import requests

from datetime import datetime
from functools import partial
from multiprocessing import Pool

from util_functions import http_get_request
from util_functions import success, warning, info


class InformationDisclosure:
    __wavs_mod__ = True

    info = {
        "name": "Information Disclosure",
        "db_table_name": "info_disc_discovered",
        "desc": "Scans for files that should be accessible",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main, options=None):
        self.main = main

        self._create_db_table()

    def _create_db_table(self):
        """ used to create database table needed to store results for this
            module. should be overwritten to meet this modules storage needs
        """
        if not self.main.db.db_table_exists(self.info['db_table_name']):
            sql_create_statement = (f'CREATE TABLE  IF NOT EXISTS {self.info["db_table_name"]}('
                                    f'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                                    f'scan_id INTEGER NOT NULL,'
                                    f'file TEXT,'
                                    f'UNIQUE(scan_id, file));')
            self.main.db.db_create_table(sql_create_statement)


    def _load_scan_results(self):
        """ loads in results from previous scans, should be overwritten to load
            in specific results needed for this module
        """
        # load directories from database, results are a list of tuples
        dirs_discovered = self.main.db.load_scan_results(self.main.id,
                                                         'directory',
                                                         'directories_discovered')

        # convert the list of tuples into a 1D list
        return [d[0] for d in dirs_discovered]

    def _save_scan_results(self, results):
        """ dont have to worry about inserting id, scan_id
        """
        self.main.db.save_scan_results(self.main.id,
                                       self.info['db_table_name'],
                                       "file",
                                       results)

    def _run_thread(self, directory, word):
        """ makes a HTTP GET request to check if a file exists. to be used as
            a thread.

            :param directory:       the directory to search for files in
            :param word:            the file name to search for
            :return (list):         a list of found files
        """
        found_files = []
        backup_extensions = self.extension_list

        # construct the url to be used in the GET request
        url = f'{self.main.get_host_url_base()}/'
        if directory:
            url += (directory + '/')

        # loop through file extensions to be searched for
        for ext in backup_extensions:
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
        start_time = datetime.now()
        # info('Starting file scan on {}:{} at {}'.format(self.main.host,
        #                                            self.main.port,
        #                                            datetime.strftime(start_time,
        #                                             '%d/%b/%Y %H:%M:%S')))
        info('Searching for information disclosure...')

        self.extension_list = self.main.db.db_get_wordlist_generic('info_disc',
                                                                   'extension')
        self.extension_list = [ext[0] for ext in self.extension_list]

        word_list = self.main.db.db_get_wordlist('dir_test', 'general')

        # create the threads
        # need to let user change the number of threads used
        thread_pool = Pool(self.main.options['threads'])

        files_found = []

        # loop through the list of directories found by _dir_scanner
        dirs_discovered = self._load_scan_results()
        for directory in dirs_discovered:
            # use partial to allow more parameters passed to map
            func = partial(self._run_thread, directory)

            # use threads to scan for files
            files_found += thread_pool.map(func, word_list)

        # remove None results
        files_found = [file for file in files_found if file != None]
        files_found = [file for sublist in files_found for file in sublist]

        thread_pool.close()
        thread_pool.join()

        self._save_scan_results(files_found)

        end_time = datetime.now()
        #info('File search completed. Elapsed: {}'.format(end_time - start_time))
