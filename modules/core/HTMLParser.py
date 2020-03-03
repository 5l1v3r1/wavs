from multiprocessing import Pool
from bs4 import BeautifulSoup

from util_functions import success, info
from util_functions import http_get_request


class HTMLParser:
    __wavs_mod__ = True

    info = {
        "name": "HTML Parser",
        "db_table_name": "parameters_discovered",
        "desc": "Takes a webpage and parses the HTML to find params to inject",
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
            sql_create_statement = ('CREATE TABLE IF NOT EXISTS '
                                    f'{self.info["db_table_name"]}('
                                    'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                                    'scan_id INTEGER NOT NULL,'
                                    'method TEXT NOT NULL,'
                                    'action TEXT NOT NULL,'
                                    'parameter TEXT NOT NULL,'
                                    'UNIQUE(scan_id, method, '
                                    'action, parameter));')
            self.main.db.db_create_table(sql_create_statement)

    def _load_scan_results(self):
        """ loads in results from previous scans, should be overwritten to load
            in specific results needed for this module
        """
        # load directories from database, results are a list of tuples
        files_discovered = self.main.db.load_scan_results(self.main.id,
                                                          'file',
                                                          'files_discovered')

        # convert the list of tuples into a 1D list
        return [f[0] for f in files_discovered]

    def _save_scan_results(self, results):
        full_list = []
        for r in results:
            full_list.append((r['method'],
                              r['action'],
                              ', '.join(r['params'])))

        self.main.db.save_scan_results(self.main.id,
                                       self.info['db_table_name'],
                                       "method, action, parameter",
                                       full_list)

    def _extract_link_params(self, link, directory_path):
        assert('?' in link)

        action, params = link.split('?')

        stored_params = []
        for param in params.split('&'):
            stored_params.append(param.split('=')[0])

        return {'method': 'GET',
                'action': directory_path + action,
                'params': stored_params}

    def _extract_links(self, html, directory_path):
        """ extract anchor links out of html data

            :param html:        a beautiful soup html object
            :return (list):     a list of links found in the html
        """
        links = []

        # loop through all the anchor tags
        for link in html.find_all('a'):
            href = link.get('href')

            if not href:
                continue

            # we only want links with parameters in
            if '?' not in href:
                continue

            # we assume if it is an absolute path it is external and ignore it
            if any(x in href for x in ['http://', 'https://']):
                continue

            # extract the parameters from the link
            links.append(self._extract_link_params(link.get('href'),
                                                   directory_path))

        return links

    def _extract_form_params(self, form, field):
        ''' from an html form, build param data

            :param form:        a beautiful soup form object
            :param field:       a beautiful soup field object
            :return (dict):     a dictionary with param data
        '''

        action = form.get('action')

        if not action:
            return None

        if any(x in action for x in ['http://', 'https://']):
            return None

        return field.get('name')

    def _extract_forms(self, html, directory_path):
        """ extract params from html forms

            :param html:        a beautiful soup html object
            :return (list):     a list of params found in the html
        """

        all_forms = []
        forms = html.find_all('form')

        if not forms:
            return []

        for form in forms:
            form_params = []
            for field in form.find_all('input'):
                field_name = self._extract_form_params(form, field)
                if field_name:
                    form_params.append(field_name)

            all_forms.append({'method': form.get('method'),
                              'action': directory_path + form.get('action'),
                              'params': form_params})

        return all_forms

    def _run_thread(self, webpage):
        """ runs in a thread. parses a webpage's html for form and links, then
            extracts parameters to inject attacks into

            :param webpage:         a beautiful soup html parser object
            :return (list):         a list of dictionaries containing params
        """
        # get the html
        url = f'{self.main.get_host_url_base()}/{webpage}'
        html = http_get_request(url, self.main.cookies).text

        # look for params to inject into
        soup = BeautifulSoup(html, 'html.parser')

        directory_path = ''
        # if the webpage has a directory
        if '/' in webpage:
            path_split = webpage.split('/')
            directory_path = '/'.join(path_split[:-1]) + '/'

        params = []
        params.extend(self._extract_links(soup, directory_path))
        params.extend(self._extract_forms(soup, directory_path))

        return params

    def run_module(self):
        """ the entrypoint into the module.

            takes any found webpages and uses threads to extract params from
            the html.
        """
        info('Parsing HTML...')

        # get the list of found pages
        found_pages = self._load_scan_results()

        # if there are no found pages, theres no need to run this module
        if not found_pages:
            return

        # pass the found pages to threads
        thread_pool = Pool(self.main.options['threads'])
        found_params = thread_pool.map(self._run_thread, found_pages)

        # close the threads
        thread_pool.close()
        thread_pool.join()

        # clean up the results from the threads
        final = []
        found_params = [final.extend(p) for p in found_params if p]
        final = list(filter(None, final))

        # remove duplicate found parameters
        final = [i for n, i in enumerate(final) if i not in final[n + 1:]]

        if self.main.options['verbose']:
            for params in final:
                success(f'Found params: {params["action"]}/'
                        f'{" ".join(params["params"])}', prepend='  ')

        self._save_scan_results(final)
