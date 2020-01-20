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
        self.directories_found = []

        # seed the random number generator
        random.seed(datetime.now())

        self.modules = []
        self.modules.append(load_module("scanners", "DirectoryScanner")(self))

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


    def _thread_file_scan(self, directory, word):
        """ makes a HTTP GET request to check if a file exists. to be used as
            a thread.

            :param directory:       the directory to search for files in
            :param word:            the file name to search for
            :return (list):         a list of found files
        """
        found_files = []

        # construct the url to be used in the GET request
        url = 'http://{}:{}/'.format(self.host, self.port)
        if directory:
            url += (directory + '/')

        # loop through file extensions to be searched for
        for ext in self.file_extensions:
            # make the GET request for the file
            resp = requests.get(url + '{}{}'.format(word, ext))

            # check if the response code is a success code
            if (resp.status_code in self.success_codes):
                # if the directory is not an empty string i.e. if it is not
                # searching the root directory
                if directory:
                    found_files.append('{}/{}{}'.format(directory, word, ext))
                else:
                    found_files.append('{}{}'.format(word, ext))

        # only return a list if files were actually found
        if found_files:
            return found_files


    def _file_scanner(self):
        """ method that loads in a file wordlist and uses thread to search for
            the files

            :return:
        """
        # TODO: create a file wordlist
        word_list = db_get_wordlist('directory', 'general')

        # create the threads
        # need to let user change the number of threads used
        thread_pool = Pool(8)

        self.files_found = []

        # loop through the list of directories found by _dir_scanner
        for directory in self.directories_found:
            # use partial to allow more parameters passed to map
            func = partial(self._thread_file_scan, directory)

            # use threads to scan for files
            self.files_found += thread_pool.map(func, word_list)

        # remove None results
        self.files_found = [file for file in self.files_found if file != None]
        self.files_found = [file for sublist in self.files_found for file in sublist]

        thread_pool.close()
        thread_pool.join()

        print(self.files_found)



class Test(unittest.TestCase):
    pass

if __name__ == '__main__':
    wscan = WebScanner(args.host, args.port)
    wscan.run_modules()
    #wscan._dir_scanner()
    #wscan._file_scanner()
