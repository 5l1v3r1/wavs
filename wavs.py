#/usr/bin/python3

# author:       Ryan Ritchie
# student no:   17019225
# email:        ryan2.ritchie@live.uwe.ac.uk
# file:         wavs.py

# core imports
import sys
import requests
import argparse
import unittest

from datetime import datetime
from multiprocessing import Pool
from functools import partial

# my imports
from utils import success, warning, info
from utils import db_get_wordlist
from utils import load_module
from utils import cookie_parse

# argument parsing
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('host', help='The url of the web application to be scanned')
arg_parser.add_argument('--port', type=int, default=80, help='The port the web application is running on')
arg_parser.add_argument('--cookies', help='Cookies to be included in requests, <cookie_name>=<cookie_value>,[...]')
arg_parser.add_argument('--restricted_paths', help='Paths which should not be visited, /restrict/path/1,/restrict/path/2')
args = arg_parser.parse_args()

class WebScanner():
    def __init__(self, host, port=80, cookies='', restrict_paths=''):
        # TODO: handle http/https
        self.host = host
        self.port = port
        self.cookies = cookie_parse(cookies)

        if ',' in restrict_paths:
            self.restrict_paths = restrict_paths.split(',')
        else:
            self.restrict_paths = [restrict_paths]

        # TODO: add way to change success codes
        self.success_codes = [200, 201, 202, 203, 204, 301, 302, 303, 304]
        self.file_extensions = ['.html', '.php']

        # dictionary to hold scan results, custom modules can add results
        self.scan_results = {
            'directories_found': [],
            'files_found': [],
            'params_found': []
        }

        # TODO: load modules in from config file
        self.modules = []
        self.modules.append(load_module("scanners", "InitialScanner")(self))
        self.modules.append(load_module("scanners", "DirectoryScanner")(self))
        self.modules.append(load_module("scanners", "FileScanner")(self))
        self.modules.append(load_module("scanners", "Spider")(self))
        self.modules.append(load_module("scanners", "HTMLParser")(self))

    def run_modules(self):
        for module in self.modules:
            module.run_module()


class Test(unittest.TestCase):
    pass

if __name__ == '__main__':
    wscan = WebScanner(args.host, args.port, args.cookies, args.restricted_paths)
    wscan.run_modules()
    #wscan._dir_scanner()
    #wscan._file_scanner()
