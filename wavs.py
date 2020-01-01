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
from multiprocessing import Pool

# my imports
from utils import success, warning, info

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
        self.directories_found = []

    def _check_wrong_200(self):
        #TODO: need to try random long string to see if we get 200
        # that means the application is returning 200 for everything
        # need to fuzz
        should_not_find = 'lkjaslkdjaslkdjaklsjdakl897u9821khad'
        resp = requests.get('http://{}:{}/{}'.format(self.host, self.port, should_not_find))

        if resp.status_code == 200:
            warning('/{} returned code 200. Should swith to fuzzing'.format(should_not_find))

    def _thread_scan(self, word):
        resp = requests.get('http://{}:{}/{}'.format(self.host, self.port, word))

        if (resp.status_code in self.success_codes):
            return word

    def scan(self, wordlist_path):
        print('[*] Starting scan on {}:{}'.format(self.host, self.port))

        # check if application returns 200 for random string
        self._check_wrong_200()

        thread_pool = Pool(8)
        # read lines in from the wordlist
        # TODO: store word lists in database
        with open(wordlist_path, 'r') as f:
            word_list = f.read()
            word_list = word_list.split('\n')

        self.directories_found = thread_pool.map(self._thread_scan, word_list)
        self.directories_found = [directory for directory in self.directories_found if directory]

        thread_pool.close()
        thread_pool.join()

        print(self.directories_found)


class Test(unittest.TestCase):
    pass

if __name__ == '__main__':
    wscan = WebScanner(args.host, args.port)
    wscan.scan('/opt/SecLists/Discovery/Web-Content/raft-small-directories.txt')
