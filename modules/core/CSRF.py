from multiprocessing import Pool

from util_functions import success, warning, info


class CSRF:
    __wavs_mod__ = True

    info = {
        "name": "Cross Site Request Forgery",
        "db_table_name": "csrf_discovered",
        "wordlist_name": "csrf",
        "desc": "Searches for the lack of anti-csrf tokens in forms",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main, options=None):
        self.main = main

        self._create_db_table()

    def generate_text(self):
        # load in text to be trained
        text_list = self.main.db.get_wordlist(self.info['wordlist_name'])

        # generate a list of words based on training text
        generated_list = self.main.text_generator.generate(text_list)

        # save generated list to be run on next scan
        self.main.db.save_generated_text(generated_list,
                                         self.info['wordlist_name'])

    def _create_db_table(self):
        """ used to create database table needed to store results for this
            module. should be overwritten to meet this modules storage needs
        """
        if not self.main.db.table_exists(self.info['db_table_name']):
            sql_create_statement = (f'CREATE TABLE  IF NOT EXISTS '
                                    f'{self.info["db_table_name"]}('
                                    f'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                                    f'scan_id INTEGER NOT NULL,'
                                    f'page TEXT,'
                                    f'form TEXT,'
                                    f'UNIQUE(scan_id, page, form));')
            self.main.db.create_table(sql_create_statement)

    def _get_previous_results(self):
        """ loads in results from previous scans, should be overwritten to load
            in specific results needed for this module
        """
        # load directories from database, results are a list of tuples
        forms_discovered = self.main.db.\
            get_previous_results(self.main.id,
                              'method,action,parameter',
                              'parameters_discovered')

        # convert the list of tuples into a 1D list
        return forms_discovered

    def _save_scan_results(self, results):
        """ dont have to worry about inserting id, scan_id
        """
        self.main.db.save_scan_results(self.main.id,
                                       self.info['db_table_name'],
                                       "page,form",
                                       results)

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
                success(f'No anti-csrf tokens for: {page}/{form[2]}',
                        prepend='  ')
                return (page, form[2])

    def run_module(self):
        """ method that loads in a file wordlist and uses thread to search for
            the files

            :return:
        """

        info('Searching for CSRF...')

        self.csrf_fields = self.main.db.\
            get_wordlist(self.info['wordlist_name'])
        forms_discovered = self._get_previous_results()

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
