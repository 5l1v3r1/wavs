import requests

from datetime import datetime
from functools import partial
from multiprocessing import Pool

from utils import http_get_request
from utils import success, warning, info
from utils import db_get_wordlist, load_scan_results, save_scan_results, db_table_exists, db_create_table, db_get_wordlist_generic


class CSRF:
    __wavs_mod__ = True

    info = {
        "name": "Cross Site Request Forgery",
        "db_table_name": "csrf_discovered",
        "desc": "Searches for the lack of anti-csrf tokens in forms",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main, options=None):
        self.main = main

        self._create_db_table()

    def _create_db_table(self):
        """ used to create database table needed to store results for this
            module. should be overwritten to meet this modules storage needs
        """
        if not db_table_exists(self.info['db_table_name']):
            sql_create_statement = (f'CREATE TABLE  IF NOT EXISTS {self.info["db_table_name"]}('
                                    f'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                                    f'scan_id INTEGER NOT NULL,'
                                    f'page TEXT,'
                                    f'form TEXT,'
                                    f'UNIQUE(scan_id, page, form));')
            db_create_table(sql_create_statement)


    def _load_scan_results(self):
        """ loads in results from previous scans, should be overwritten to load
            in specific results needed for this module
        """
        # load directories from database, results are a list of tuples
        forms_discovered = load_scan_results(self.main.id, 'method,action,parameter', 'parameters_discovered')

        # convert the list of tuples into a 1D list
        return forms_discovered

    def _save_scan_results(self, results):
        """ dont have to worry about inserting id, scan_id
        """
        save_scan_results(self.main.id, self.info['db_table_name'], "page,form", results)

    def _run_thread(self, form):
        """ search through form parameters to find anti-csrf tokens
        """
        if len(form) != 3:
            warning('Internal error, not enough form elements in CSRF')
            exit()

        # give the form data human friendly names
        method = form[0]
        page = form[1]
        params = form[2]

        # were only concerned with POST requests for CSRF
        if method == 'POST':

            # split params into a list
            if ',' in params:
                params = params.split(',')
            else:
                params = [params]

            # check if param names contain any anti-csrf token params
            if not any(csrf_name in params for csrf_name in self.csrf_fields):
                success(f'No anti-csrf tokens for: {page}/{form[2]}', prepend='  ')
                return (page, form[2])

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
        info('Searching for CSRF...')

        self.csrf_fields = db_get_wordlist_generic('csrf', 'csrf_field_name')
        forms_discovered = self._load_scan_results()

        # create the threads
        # need to let user change the number of threads used
        thread_pool = Pool(self.main.options['threads'])

        csrf_discovered = []
        csrf_discovered = thread_pool.map(self._run_thread, forms_discovered)

        thread_pool.close()
        thread_pool.join()

        # remove any empty results
        csrf_discovered = [csrf for csrf in csrf_discovered if csrf]
        self._save_scan_results(csrf_discovered)

        end_time = datetime.now()
        #info('File search completed. Elapsed: {}'.format(end_time - start_time))
