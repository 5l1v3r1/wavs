import requests

from datetime import datetime
from multiprocessing import Pool
from bs4 import BeautifulSoup

from utils import success, warning, info
from utils import db_get_wordlist, load_scan_results, save_scan_results, db_table_exists, db_create_table
from utils import http_get_request

class Crawler:
    __wavs_mod__ = True

    info = {
        "name": "Site Crawler",
        "db_table_name": "files_discovered",
        "desc": "Crawls through links to find new pages",
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
            sql_create_statement = (f'CREATE TABLE IF NOT EXISTS {self.info["db_table_name"]}('
                                    f'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                                    f'scan_id INTEGER NOT NULL,'
                                    f'file TEXT,'
                                    f'UNIQUE(scan_id, file));')
            db_create_table(sql_create_statement)


    def _load_scan_results(self):
        """ loads in results from previous scans, should be overwritten to load
            in specific results needed for this module
        """
        # load directories from database, results are a list of tuples
        files_discovered = load_scan_results(self.main.id, 'file', 'files_discovered')

        # convert the list of tuples into a 1D list
        return [f[0] for f in files_discovered]

    def _save_scan_results(self, results):
        save_scan_results(self.main.id, self.info['db_table_name'], "file", results)

    def _run_thread(self, page):
        # get the html
        url = f'http://{self.main.host}:{self.main.port}/{page}'
        html = http_get_request(url, self.main.cookies).text

        # look for params to inject into
        soup = BeautifulSoup(html, 'html.parser')

        return_links = []
        for link in soup.find_all('a'):
            href = link.get('href')

            # remove blanks and param links
            if not href or href[0] == '?':
                continue

            if not any(x in href for x in ['http://', 'https://']):
                if '?' in href:
                    # get page from href
                    linked_page = href.split('?')[0]

                    if linked_page not in self.found_pages:
                        return_links.append(f'{linked_page}')

        return return_links

    def run_module(self):
        info('Crawling links...')
        # get found pages
        #found_pages = self.main.scan_results['files_found']
        self.found_pages = self._load_scan_results()

        # create the threads
        thread_pool = Pool(self.main.options['threads'])

        # run the threads with found pages
        found_links = thread_pool.map(self._run_thread, self.found_pages)

        thread_pool.close()
        thread_pool.join()

        # get rid of any null value
        final = []
        found_links = [final.extend(link) for link in found_links if link]

        # remove duplicates
        final = list(set(final))

        self._save_scan_results(final)
