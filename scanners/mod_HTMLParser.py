from multiprocessing import Pool
from bs4 import BeautifulSoup

from utils import success, warning, info
from utils import http_get_request

class HTMLParser:
    __wavs_mod__ = True

    info = {
        "name": "HTML Parser",
        "desc": "Takes a webpage and parses the HTML to find params to inject",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main, options=None):
        self.main = main

        self.options = {
            # the number of threads the directory scanner should use
            "numberOfThreads": 8
        }

    def _run_thread(self, webpage):
        # get the html
        url = f'http://{self.main.host}:{self.main.port}/{webpage}'
        html = http_get_request(url).text

        # look for params to inject into
        soup = BeautifulSoup(html, 'html.parser')
        success(soup.prettify())

    def _run_module(self):
        # get the list of found pages
        found_pages = self.main.scan_results['files_found']

        found_params = []

        # pass the found pages to threads
        pool = Pool(self.options['numberOfThreads'])
        found_params = pool.map(self._run_thread, found_pages)
