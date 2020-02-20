import requests

from datetime import datetime
from multiprocessing import Pool
from bs4 import BeautifulSoup

from utils import success, warning, info
from utils import db_get_wordlist, load_scan_results, save_scan_results, db_table_exists, db_create_table
from utils import http_get_request

# TODO: make crawler recursive
# TODO: parse sitemap.xml
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
        pass

    def _parse_link(self, link):
        # remove blanks and param links
        if not link or link[0] == '?':
            return

        if not any(x in link for x in ['http://', 'https://']):
            if '?' in link:
                # get page from href
                linked_page = link.split('?')[0]
            else:
                linked_page = link

            # check that the page actually exists first
            page_exists = http_get_request(f'{self.main.get_host_url_base()}/{linked_page}', self.main.cookies).status_code
            if page_exists in self.main.success_codes:
                return linked_page

    def _parse_links(self, page):
        # get the html
        url = f'{self.main.get_host_url_base()}/{page}'
        html = http_get_request(url, self.main.cookies).text

        # look for params to inject into
        soup = BeautifulSoup(html, 'html.parser')

        return_links = []

        # parse all hyperlinks
        for link in soup.find_all('a'):
            href = link.get('href')
            parsed_href = self._parse_link(href)

            if parsed_href:
                return_links.append(parsed_href)

        # parse all forms
        for form in soup.find_all('form'):
            action = form.get('action')
            parsed_action = self._parse_link(action)

            if parsed_action:
                return_links.append(parsed_action)

        return return_links

    def run_module(self):
        info('Crawling links...')

        # get found pages
        self.found_pages = self._load_scan_results()

        # loop through all pages found so far
        loop_pages = self.found_pages
        for page in loop_pages:
            for link in self._parse_links(page):
                if not link in loop_pages:
                    success(f'Found page: {link}', prepend='  ')
                    loop_pages.append(link)

        self._save_scan_results(loop_pages)
