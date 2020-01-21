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
import random
import string

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

        # TODO: find a better way to return module results
        self.directories_found = []
        self.files_found = []

        # seed the random number generator
        random.seed(datetime.now())

        # TODO: load modules in from config file
        self.modules = []
        self.modules.append(load_module("scanners", "DirectoryScanner")(self))
        self.modules.append(load_module("scanners", "FileScanner")(self))

    def run_modules(self):
        for module in self.modules:
            module._run_module()


    def _check_wrong_200(self):
        ''' method checks if a random string returns a 200 success code.
            a 200 code would mean the web application is returning 200 for
            all requests.

            :param:
            :return:
        '''

        # construct a random string of length 10
        should_not_find = ''.join(random.choice(string.ascii_lowercase) for i in range(10))

        # make a get request with random string as a directory
        resp = requests.get('http://{}:{}/{}'.format(self.host, self.port, should_not_find))

        # check for success code
        if resp.status_code == 200:
            warning('/{} returned code 200. Should swith to fuzzing'.format(should_not_find))

        # TODO: switch to fuzzing mode?


class Test(unittest.TestCase):
    pass

if __name__ == '__main__':
    wscan = WebScanner(args.host, args.port)
    wscan.run_modules()
    #wscan._dir_scanner()
    #wscan._file_scanner()
