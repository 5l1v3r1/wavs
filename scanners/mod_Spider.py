import requests

from datetime import datetime
from multiprocessing import Pool
from bs4 import BeautifulSoup

from utils import success, warning, info
from utils import db_get_wordlist
from utils import http_get_request

class Spider:
    __wavs_mod__ = True

    info = {
        "name": "Spider",
        "desc": "Crawls through links to find new pages",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main, options=None):
        self.main = main

        self.options = {
            # the number of threads the directory scanner should use
            "numberOfThreads": 8
        }

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
                if not href in self.found_links:
                    return_links.append(f'{page}/{href}')

        return return_links

    def run_module(self):
        # get found pages
        found_pages = self.main.scan_results['files_found']

        thread_pool = Pool(self.options['numberOfThreads'])

        self.found_links = found_pages
        found_links = thread_pool.map(self._run_thread, found_pages)

        thread_pool.close()
        thread_pool.join()

        # get rid of any null value
        final = []
        found_links = [final.extend(link) for link in found_links if link]

        # remove duplicates
        final = list(set(final))
        self.main.scan_results['files_found'].extend(final)
