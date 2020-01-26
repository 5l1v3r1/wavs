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

# argument parsing
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('host', help='The url of the web application to be scanned')
arg_parser.add_argument('--port', type=int, default=80, help='The port the web application is running on')
arg_parser.add_argument('--test')
args = arg_parser.parse_args()

class WebScanner():
    def __init__(self, host, port=80):
        # TODO: handle http/https
        self.host = host
        self.port = port

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
        self.modules.append(load_module("scanners", "HTMLParser")(self))

    def run_modules(self):
        for module in self.modules:
            module.run_module()


class Test(unittest.TestCase):
    pass

if __name__ == '__main__':
    wscan = WebScanner(args.host, args.port)
    wscan.run_modules()
    #wscan._dir_scanner()
    #wscan._file_scanner()
